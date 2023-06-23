// Copyright 2022 The Cobalt Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "cobalt/worker/service_worker_jobs.h"

#include "base/bind.h"
#include "base/message_loop/message_loop_current.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "cobalt/base/tokens.h"
#include "cobalt/web/environment_settings.h"
#include "cobalt/worker/extendable_event.h"
#include "net/base/mime_util.h"
#include "net/base/url_util.h"

namespace cobalt {
namespace worker {

namespace {

bool PathContainsEscapedSlash(const GURL& url) {
  const std::string path = url.path();
  return (path.find("%2f") != std::string::npos ||
          path.find("%2F") != std::string::npos ||
          path.find("%5c") != std::string::npos ||
          path.find("%5C") != std::string::npos);
}

bool IsOriginPotentiallyTrustworthy(const GURL& url) {
  // Algorithm for potentially trustworthy origin:
  //   https://w3c.github.io/webappsec-secure-contexts/#potentially-trustworthy-origin

  const url::Origin origin(url::Origin::Create(url));
  // 1. If origin is an opaque origin, return "Not Trustworthy".
  if (origin.unique()) return false;

  // 2. Assert: origin is a tuple origin.
  DCHECK(!origin.unique());
  DCHECK(url.is_valid());

  // 3. If origin’s scheme is either "https" or "wss", return "Potentially
  // Trustworthy".
  if (url.SchemeIsCryptographic()) return true;

  // 4. If origin’s host matches one of the CIDR notations 127.0.0.0/8 or
  // ::1/128 [RFC4632], return "Potentially Trustworthy".
  if (net::IsLocalhost(url)) return true;

  // 5. If the user agent conforms to the name resolution rules in
  // [let-localhost-be-localhost] and one of the following is true:
  //    origin’s host is "localhost" or "localhost."
  //    origin’s host ends with ".localhost" or ".localhost."
  // then return "Potentially Trustworthy".
  // Covered by implementation of step 4.

  // 6. If origin’s scheme is "file", return "Potentially Trustworthy".
  if (url.SchemeIsFile()) return true;

  // 7. If origin’s scheme component is one which the user agent considers to be
  // authenticated, return "Potentially Trustworthy".
  if (url.SchemeIs("h5vcc-embedded")) return true;

  // 8. If origin has been configured as a trustworthy origin, return
  // "Potentially Trustworthy".
  if (origin.host() == "web-platform.test") {
    return true;
  }

  // 9. Return "Not Trustworthy".
  return false;
}

bool PermitAnyNonRedirectedURL(const GURL&, bool did_redirect) {
  return !did_redirect;
}

}  // namespace

ServiceWorkerJobs::ServiceWorkerJobs(
    ServiceWorkerContext* service_worker_context,
    network::NetworkModule* network_module, base::MessageLoop* message_loop)
    : service_worker_context_(service_worker_context),
      message_loop_(message_loop) {
  DCHECK_EQ(message_loop_, base::MessageLoop::current());
  fetcher_factory_.reset(new loader::FetcherFactory(network_module));

  script_loader_factory_.reset(new loader::ScriptLoaderFactory(
      "ServiceWorkerJobs", fetcher_factory_.get()));
}

ServiceWorkerJobs::~ServiceWorkerJobs() {}

void ServiceWorkerJobs::PromiseErrorData::Reject(
    std::unique_ptr<JobPromiseType> promise) const {
  DCHECK(promise);
  if (message_type_ != script::kNoError) {
    promise->Reject(GetSimpleExceptionType(message_type_));
  } else {
    promise->Reject(new web::DOMException(exception_code_, message_));
  }
}

std::unique_ptr<ServiceWorkerJobs::Job> ServiceWorkerJobs::CreateJob(
    JobType type, const url::Origin& storage_key, const GURL& scope_url,
    const GURL& script_url, std::unique_ptr<JobPromiseType> promise,
    web::Context* client) {
  TRACE_EVENT2("cobalt::worker", "ServiceWorkerJobs::CreateJob()", "type", type,
               "script_url", script_url.spec());
  // Algorithm for Create Job:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#create-job
  // 1. Let job be a new job.
  // 2. Set job’s job type to jobType.
  // 3. Set job’s storage key to storage key.
  // 4. Set job’s scope url to scopeURL.
  // 5. Set job’s script url to scriptURL.
  // 6. Set job’s job promise to promise.
  // 7. Set job’s client to client.
  std::unique_ptr<Job> job(new Job(type, storage_key, scope_url, script_url,
                                   client, std::move(promise)));
  // 8. If client is not null, set job’s referrer to client’s creation URL.
  if (client) {
    job->referrer = client->environment_settings()->creation_url();
  }
  // 9. Return job.
  return job;
}

void ServiceWorkerJobs::ScheduleJob(std::unique_ptr<Job> job) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::ScheduleJob()");
  DCHECK(job);

  if (base::MessageLoop::current() != message_loop()) {
    DCHECK(message_loop());
    message_loop()->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&ServiceWorkerJobs::ScheduleJob,
                                  base::Unretained(this), std::move(job)));
    return;
  }
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Algorithm for Schedule Job:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#schedule-job
  // 1. Let jobQueue be null.

  // 2. Let jobScope be job’s scope url, serialized.
  std::string job_scope = job->scope_url.spec();

  // 3. If scope to job queue map[jobScope] does not exist, set scope to job
  // queue map[jobScope] to a new job queue.
  auto job_queue_iterator_for_scope = job_queue_map_.find(job_scope);
  if (job_queue_iterator_for_scope == job_queue_map_.end()) {
    auto insertion = job_queue_map_.emplace(
        job_scope, std::unique_ptr<JobQueue>(new JobQueue()));
    DCHECK(insertion.second);
    job_queue_iterator_for_scope = insertion.first;
  }

  // 4. Set jobQueue to scope to job queue map[jobScope].
  DCHECK(job_queue_iterator_for_scope != job_queue_map_.end());
  JobQueue* job_queue = job_queue_iterator_for_scope->second.get();

  // 5. If jobQueue is empty, then:
  if (job_queue->empty()) {
    // 5.1. Set job’s containing job queue to jobQueue, and enqueue job to
    // jobQueue.
    job->containing_job_queue = job_queue;
    if (!service_worker_context_->IsWebContextRegistered(job->client)) {
      // Note: The client that requested the job has already exited and isn't
      // able to handle the promise.
      job->containing_job_queue->PrepareJobForClientShutdown(job, job->client);
    }
    job_queue->Enqueue(std::move(job));

    // 5.2. Invoke Run Job with jobQueue.
    RunJob(job_queue);
  } else {
    // 6. Else:
    // 6.1. Let lastJob be the element at the back of jobQueue.
    {
      auto last_item = job_queue->LastItem();
      Job* last_job = last_item.first;

      // 6.2. If job is equivalent to lastJob and lastJob’s job promise has not
      // settled, append job to lastJob’s list of equivalent jobs.
      DCHECK(last_job);
      base::AutoLock lock(last_job->equivalent_jobs_promise_mutex);
      if (ReturnJobsAreEquivalent(job.get(), last_job) && last_job->promise &&
          last_job->promise->is_pending()) {
        last_job->equivalent_jobs.push_back(std::move(job));
        return;
      }
    }

    // 6.3. Else, set job’s containing job queue to jobQueue, and enqueue job to
    // jobQueue.
    job->containing_job_queue = job_queue;
    if (!service_worker_context_->IsWebContextRegistered(job->client)) {
      // Note: The client that requested the job has already exited and isn't
      // able to handle the promise.
      job->containing_job_queue->PrepareJobForClientShutdown(job, job->client);
    }
    job_queue->Enqueue(std::move(job));
  }
  DCHECK(!job);
}

bool ServiceWorkerJobs::ReturnJobsAreEquivalent(Job* one, Job* two) {
  // Algorithm for Two jobs are equivalent:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#dfn-job-equivalent
  DCHECK(one);
  DCHECK(two);
  if (!one || !two) {
    return false;
  }

  // Two jobs are equivalent when their job type is the same and:
  if (one->type != two->type) {
    return false;
  }

  // For register and update jobs, their scope url, script url, worker type, and
  // update via cache mode are the same.
  if ((one->type == kRegister || one->type == kUpdate) &&
      (one->scope_url == two->scope_url) &&
      (one->script_url == two->script_url) &&
      (one->update_via_cache == two->update_via_cache)) {
    return true;
  }

  // For unregister jobs, their scope url is the same.
  return (one->type == kUnregister) && (one->scope_url == two->scope_url);
}

void ServiceWorkerJobs::RunJob(JobQueue* job_queue) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::RunJob()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Algorithm for Run Job:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#run-job-algorithm

  // 1. Assert: jobQueue is not empty.
  DCHECK(job_queue && !job_queue->empty());
  if (!job_queue || job_queue->empty()) {
    return;
  }

  // 2. Queue a task to run these steps:
  message_loop()->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&ServiceWorkerJobs::RunJobTask,
                                base::Unretained(this), job_queue));
}

void ServiceWorkerJobs::RunJobTask(JobQueue* job_queue) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::RunJobTask()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Task for "Run Job" to run in the service worker thread.
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#run-job-algorithm
  DCHECK(job_queue);
  if (!job_queue) return;
  DCHECK(!job_queue->empty());

  // 2.1 Let job be the first item in jobQueue.
  Job* job = job_queue->FirstItem();

  DCHECK(job);
  switch (job->type) {
    // 2.2 If job’s job type is register, run Register with job in parallel.
    case kRegister:
      Register(job);
      break;

    // 2.3 Else if job’s job type is update, run Update with job in parallel.
    case kUpdate:
      Update(job);
      break;

    // 2.4 Else if job’s job type is unregister, run Unregister with job in
    // parallel.
    case kUnregister:
      Unregister(job);
      break;
    default:
      NOTREACHED();
  }
}

void ServiceWorkerJobs::Register(Job* job) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::Register()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  DCHECK(job);
  // Algorithm for Register:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#register-algorithm

  // 1. If the result of running potentially trustworthy origin with the origin
  // of job’s script url as the argument is Not Trusted, then:
  if (!IsOriginPotentiallyTrustworthy(job->script_url)) {
    // 1.1. Invoke Reject Job Promise with job and "SecurityError" DOMException.
    RejectJobPromise(
        job, PromiseErrorData(
                 web::DOMException::kSecurityErr,
                 "Service Worker Register failed: Script URL is Not Trusted."));
    // 1.2. Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }

  // 2. If job’s script url's origin and job’s referrer's origin are not same
  // origin, then:
  const url::Origin job_script_origin(url::Origin::Create(job->script_url));
  const url::Origin job_referrer_origin(url::Origin::Create(job->referrer));
  if (!job_script_origin.IsSameOriginWith(job_referrer_origin)) {
    // 2.1. Invoke Reject Job Promise with job and "SecurityError" DOMException.
    RejectJobPromise(
        job,
        PromiseErrorData(
            web::DOMException::kSecurityErr,
            base::StringPrintf(
                ServiceWorkerConsts::
                    kServiceWorkerRegisterScriptOriginNotSameError,
                job->script_url.spec().c_str(), job->referrer.spec().c_str())));
    // 2.2. Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }

  // 3. If job’s scope url's origin and job’s referrer's origin are not same
  // origin, then:
  const url::Origin job_scope_origin(url::Origin::Create(job->scope_url));
  if (!job_scope_origin.IsSameOriginWith(job_referrer_origin)) {
    // 3.1. Invoke Reject Job Promise with job and "SecurityError" DOMException.
    RejectJobPromise(
        job,
        PromiseErrorData(
            web::DOMException::kSecurityErr,
            base::StringPrintf(
                ServiceWorkerConsts::
                    kServiceWorkerRegisterScopeOriginNotSameError,
                job->scope_url.spec().c_str(), job->referrer.spec().c_str())));

    // 3.2. Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }

  // 4. Let registration be the result of running Get Registration given job’s
  // storage key and job’s scope url.
  scoped_refptr<ServiceWorkerRegistrationObject> registration =
      service_worker_context_->registration_map()->GetRegistration(
          job->storage_key, job->scope_url);

  // 5. If registration is not null, then:
  if (registration) {
    // 5.1 Let newestWorker be the result of running the Get Newest Worker
    // algorithm passing registration as the argument.
    const scoped_refptr<ServiceWorkerObject>& newest_worker =
        registration->GetNewestWorker();

    // 5.2 If newestWorker is not null, job’s script url equals newestWorker’s
    // script url, job’s worker type equals newestWorker’s type, and job’s
    // update via cache mode's value equals registration’s update via cache
    // mode, then:
    if (newest_worker && job->script_url == newest_worker->script_url()) {
      // 5.2.1 Invoke Resolve Job Promise with job and registration.
      ResolveJobPromise(job, registration);

      // 5.2.2 Invoke Finish Job with job and abort these steps.
      FinishJob(job);
      return;
    }
  } else {
    // 6. Else:

    // 6.1 Invoke Set Registration algorithm with job’s storage key, job’s scope
    // url, and job’s update via cache mode.
    registration = service_worker_context_->registration_map()->SetRegistration(
        job->storage_key, job->scope_url, job->update_via_cache);
  }

  // 7. Invoke Update algorithm passing job as the argument.
  Update(job);
}

void ServiceWorkerJobs::Update(Job* job) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::Update()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  DCHECK(job);
  // Algorithm for Update:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#update-algorithm

  // 1. Let registration be the result of running Get Registration given job’s
  //    storage key and job’s scope url.
  scoped_refptr<ServiceWorkerRegistrationObject> registration =
      service_worker_context_->registration_map()->GetRegistration(
          job->storage_key, job->scope_url);

  // 2. If registration is null, then:
  if (!registration) {
    // 2.1. Invoke Reject Job Promise with job and TypeError.
    RejectJobPromise(job, PromiseErrorData(script::kSimpleTypeError));

    // 2.2. Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }
  // 3. Let newestWorker be the result of running Get Newest Worker algorithm
  //    passing registration as the argument.
  const scoped_refptr<ServiceWorkerObject>& newest_worker =
      registration->GetNewestWorker();

  // 4. If job’s job type is update, and newestWorker is not null and its script
  //    url does not equal job’s script url, then:
  if ((job->type == kUpdate) && newest_worker &&
      (newest_worker->script_url() != job->script_url)) {
    // 4.1 Invoke Reject Job Promise with job and TypeError.
    RejectJobPromise(job, PromiseErrorData(script::kSimpleTypeError));

    // 4.2 Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }

  auto state(
      base::MakeRefCounted<UpdateJobState>(job, registration, newest_worker));

  // 5. Let referrerPolicy be the empty string.
  // 6. Let hasUpdatedResources be false.
  state->has_updated_resources = false;
  // 7. Let updatedResourceMap be an ordered map where the keys are URLs and the
  //    values are responses.
  // That is located in job->updated_resource_map.

  // 8. Switching on job’s worker type, run these substeps with the following
  //    options:
  //    - "classic"
  //        Fetch a classic worker script given job’s serialized script url,
  //        job’s client, "serviceworker", and the to-be-created environment
  //        settings object for this service worker.
  //    - "module"
  //        Fetch a module worker script graph given job’s serialized script
  //        url, job’s client, "serviceworker", "omit", and the to-be-created
  //        environment settings object for this service worker.
  // To perform the fetch given request, run the following steps:
  //   8.1.  Append `Service-Worker`/`script` to request’s header list.
  net::HttpRequestHeaders headers;
  headers.SetHeader("Service-Worker", "script");
  //   8.2.  Set request’s cache mode to "no-cache" if any of the following are
  //         true:
  //          - registration’s update via cache mode is not "all".
  //          - job’s force bypass cache flag is set.
  //          - newestWorker is not null and registration is stale.
  //   8.3.  Set request’s service-workers mode to "none".
  //   8.4.  If the is top-level flag is unset, then return the result of
  //         fetching request.
  //   8.5.  Set request’s redirect mode to "error".
  csp::SecurityCallback csp_callback = base::Bind(&PermitAnyNonRedirectedURL);
  //   8.6.  Fetch request, and asynchronously wait to run the remaining steps
  //         as part of fetch’s process response for the response response.
  // Note: The CSP check for the script_url is done in StartRegister, where
  // the client's CSP list can still be referred to.
  loader::Origin origin = loader::Origin(job->script_url.GetOrigin());
  job->loader = script_loader_factory_->CreateScriptLoader(
      job->script_url, origin, csp_callback,
      base::Bind(&ServiceWorkerJobs::UpdateOnContentProduced,
                 base::Unretained(this), state),
      base::Bind(&ServiceWorkerJobs::UpdateOnResponseStarted,
                 base::Unretained(this), state),
      base::Bind(&ServiceWorkerJobs::UpdateOnLoadingComplete,
                 base::Unretained(this), state),
      std::move(headers),
      /*skip_fetch_intercept=*/true);
}

bool ServiceWorkerJobs::UpdateOnResponseStarted(
    scoped_refptr<UpdateJobState> state, loader::Fetcher* fetcher,
    const scoped_refptr<net::HttpResponseHeaders>& headers) {
  std::string content_type;
  bool mime_type_is_javascript = false;
  if (headers->GetNormalizedHeader("Content-type", &content_type)) {
    //   8.7.  Extract a MIME type from the response’s header list. If this MIME
    //         type (ignoring parameters) is not a JavaScript MIME type, then:
    if (content_type.empty()) {
      RejectJobPromise(
          state->job,
          PromiseErrorData(
              web::DOMException::kSecurityErr,
              ServiceWorkerConsts::kServiceWorkerRegisterNoMIMEError));
      return true;
    }
    for (auto mime_type : ServiceWorkerConsts::kJavaScriptMimeTypes) {
      if (net::MatchesMimeType(mime_type, content_type)) {
        mime_type_is_javascript = true;
        break;
      }
    }
  }
  if (!mime_type_is_javascript) {
    //   8.7.1. Invoke Reject Job Promise with job and "SecurityError"
    //          DOMException.
    //   8.7.2. Asynchronously complete these steps with a network error.
    RejectJobPromise(
        state->job,
        PromiseErrorData(
            web::DOMException::kSecurityErr,
            base::StringPrintf(
                ServiceWorkerConsts::kServiceWorkerRegisterBadMIMEError,
                content_type.c_str())));
    return true;
  }
  //   8.8.  Let serviceWorkerAllowed be the result of extracting header list
  //         values given `Service-Worker-Allowed` and response’s header list.
  std::string service_worker_allowed;
  bool service_worker_allowed_exists = headers->GetNormalizedHeader(
      ServiceWorkerConsts::kServiceWorkerAllowed, &service_worker_allowed);
  //   8.9.  Set policyContainer to the result of creating a policy container
  //         from a fetch response given response.
  state->script_headers = headers;
  //   8.10. If serviceWorkerAllowed is failure, then:
  //   8.10.1  Asynchronously complete these steps with a network error.
  //   8.11. Let scopeURL be registration’s scope url.
  GURL scope_url = state->registration->scope_url();
  //   8.12. Let maxScopeString be null.
  base::Optional<std::string> max_scope_string;
  //   8.13. If serviceWorkerAllowed is null, then:
  if (!service_worker_allowed_exists || service_worker_allowed.empty()) {
    //   8.13.1. Let resolvedScope be the result of parsing "./" using job’s
    //           script url as the base URL.
    //   8.13.2. Set maxScopeString to "/", followed by the strings in
    //           resolvedScope’s path (including empty strings), separated
    //           from each other by "/".
    max_scope_string = state->job->script_url.GetWithoutFilename().path();
  } else {
    //   8.14. Else:
    //   8.14.1. Let maxScope be the result of parsing serviceWorkerAllowed
    //           using job’s script url as the base URL.
    GURL max_scope = state->job->script_url.Resolve(service_worker_allowed);
    //   8.14.2. If maxScope’s origin is job’s script url's origin, then:
    if (loader::Origin(state->job->script_url) == loader::Origin(max_scope)) {
      //   8.14.2.1. Set maxScopeString to "/", followed by the strings in
      //             maxScope’s path (including empty strings), separated from
      //             each other by "/".
      max_scope_string = max_scope.path();
    }
  }
  //   8.15. Let scopeString be "/", followed by the strings in scopeURL’s
  //         path (including empty strings), separated from each other by "/".
  std::string scope_string = scope_url.path();
  //   8.16. If maxScopeString is null or scopeString does not start with
  //         maxScopeString, then:
  if (!max_scope_string.has_value() ||
      !base::StartsWith(scope_string, max_scope_string.value(),
                        base::CompareCase::SENSITIVE)) {
    //   8.16.1. Invoke Reject Job Promise with job and "SecurityError"
    //           DOMException.
    //   8.16.2. Asynchronously complete these steps with a network error.
    RejectJobPromise(
        state->job,
        PromiseErrorData(
            web::DOMException::kSecurityErr,
            base::StringPrintf(
                ServiceWorkerConsts::kServiceWorkerRegisterBadScopeError,
                scope_string.c_str())));
    return true;
  }
  return true;
}

void ServiceWorkerJobs::UpdateOnContentProduced(
    scoped_refptr<UpdateJobState> state, const loader::Origin& last_url_origin,
    std::unique_ptr<std::string> content) {
  TRACE_EVENT0("cobalt::worker",
               "ServiceWorkerJobs::UpdateOnContentProduced()");
  DCHECK(content);
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Note: There seems to be missing handling of network errors here.
  //   8.17. Let url be request’s url.
  //   8.18. Set updatedResourceMap[url] to response.
  auto result = state->updated_resource_map.emplace(std::make_pair(
      state->job->script_url,
      ScriptResource(std::move(content), state->script_headers)));
  // Assert that the insert was successful.
  DCHECK(result.second);
  std::string* updated_script_content =
      result.second ? result.first->second.content.get() : nullptr;
  DCHECK(updated_script_content);
  //   8.19. If response’s cache state is not "local", set registration’s last
  //         update check time to the current time.
  scoped_refptr<ServiceWorkerRegistrationObject> registration =
      service_worker_context_->registration_map()->GetRegistration(
          state->job->storage_key, state->job->scope_url);
  if (registration) {
    registration->set_last_update_check_time(base::Time::Now());
    service_worker_context_->registration_map()->PersistRegistration(
        registration->storage_key(), registration->scope_url());
  }
  // TODO(b/228904017):
  //   8.20. Set hasUpdatedResources to true if any of the following are true:
  //          - newestWorker is null.
  //          - newestWorker’s script url is not url or newestWorker’s type is
  //            not job’s worker type.
  // Note: Cobalt only supports 'classic' worker type.
  //          - newestWorker’s script resource map[url]'s body is not
  //            byte-for-byte identical with response’s body.
  if (state->newest_worker == nullptr) {
    state->has_updated_resources = true;
  } else {
    if (state->newest_worker->script_url() != state->job->script_url) {
      state->has_updated_resources = true;
    } else {
      const ScriptResource* newest_worker_script_resource =
          state->newest_worker->LookupScriptResource(state->job->script_url);
      std::string* newest_worker_script_content =
          newest_worker_script_resource
              ? newest_worker_script_resource->content.get()
              : nullptr;
      if (!newest_worker_script_content || !updated_script_content ||
          (*newest_worker_script_content != *updated_script_content)) {
        state->has_updated_resources = true;
      }
    }
  }
}

void ServiceWorkerJobs::UpdateOnLoadingComplete(
    scoped_refptr<UpdateJobState> state,
    const base::Optional<std::string>& error) {
  TRACE_EVENT0("cobalt::worker",
               "ServiceWorkerJobs::UpdateOnLoadingComplete()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  bool check_promise = !state->job->no_promise_okay;
  if (state->job->no_promise_okay && !state->job->client &&
      service_worker_context_->web_context_registrations().size() > 0) {
    state->job->client =
        *(service_worker_context_->web_context_registrations().begin());
  }
  if ((check_promise && !state->job->promise.get()) || !state->job->client) {
    // The job is already rejected, which means there was an error, or the
    // client is already shutdown, so finish the job and skip the remaining
    // steps.
    FinishJob(state->job);
    return;
  }

  if (error) {
    RejectJobPromise(
        state->job,
        PromiseErrorData(web::DOMException::kSecurityErr, error.value()));
    if (state->newest_worker == nullptr) {
      service_worker_context_->registration_map()->RemoveRegistration(
          state->job->storage_key, state->job->scope_url);
    }
    FinishJob(state->job);
    return;
  }

  //   8.21. If hasUpdatedResources is false and newestWorker’s classic
  //         scripts imported flag is set, then:
  if (!state->has_updated_resources && state->newest_worker &&
      state->newest_worker->classic_scripts_imported()) {
    // This checks if there are any updates to already stored importScripts
    // resources.
    // TODO(b/259731731): worker_global_scope_ is set in
    // ServiceWorkerObject::Initialize, part of the RunServiceWorkerAlgorithm.
    // For persisted service workers this may not be called before SoftUpdate,
    // find a way to ensure worker_global_scope_ is not null in that case.
    if (state->newest_worker->worker_global_scope() != nullptr &&
        state->newest_worker->worker_global_scope()
            ->LoadImportsAndReturnIfUpdated(
                state->newest_worker->script_resource_map(),
                &state->updated_resource_map)) {
      state->has_updated_resources = true;
    }
  }
  //   8.22. Asynchronously complete these steps with response.

  // When the algorithm asynchronously completes, continue the rest of these
  // steps, with script being the asynchronous completion value.
  auto entry = state->updated_resource_map.find(state->job->script_url);
  auto* script = entry != state->updated_resource_map.end()
                     ? entry->second.content.get()
                     : nullptr;
  // 9. If script is null or Is Async Module with script’s record, script’s
  //    base URL, and {} it true, then:
  if (script == nullptr) {
    // 9.1. Invoke Reject Job Promise with job and TypeError.
    RejectJobPromise(state->job, PromiseErrorData(script::kSimpleTypeError));

    // 9.2. If newestWorker is null, then remove registration
    //      map[(registration’s storage key, serialized scopeURL)].
    if (state->newest_worker == nullptr) {
      service_worker_context_->registration_map()->RemoveRegistration(
          state->job->storage_key, state->job->scope_url);
    }
    // 9.3. Invoke Finish Job with job and abort these steps.
    FinishJob(state->job);
    return;
  }

  // 10. If hasUpdatedResources is false, then:
  if (!state->has_updated_resources) {
    // 10.1. Set registration’s update via cache mode to job’s update via cache
    //       mode.
    state->registration->set_update_via_cache_mode(
        state->job->update_via_cache);

    // 10.2. Invoke Resolve Job Promise with job and registration.
    ResolveJobPromise(state->job, state->registration);

    // 10.3. Invoke Finish Job with job and abort these steps.
    FinishJob(state->job);
    return;
  }

  // 11. Let worker be a new service worker.
  ServiceWorkerObject::Options options(
      "ServiceWorker", state->job->client->web_settings(),
      state->job->client->network_module(), state->registration);
  options.web_options.platform_info = state->job->client->platform_info();
  options.web_options.service_worker_context =
      state->job->client->service_worker_context();
  scoped_refptr<ServiceWorkerObject> worker(new ServiceWorkerObject(options));
  // 12. Set worker’s script url to job’s script url, worker’s script
  //     resource to script, worker’s type to job’s worker type, and worker’s
  //     script resource map to updatedResourceMap.
  // -> The worker's script resource is set in the resource map at step 8.18.
  worker->set_script_url(state->job->script_url);
  worker->set_script_resource_map(std::move(state->updated_resource_map));
  // 13. Append url to worker’s set of used scripts.
  worker->AppendToSetOfUsedScripts(state->job->script_url);
  // 14. Set worker’s script resource’s policy container to policyContainer.
  DCHECK(state->script_headers);
  // 15. Let forceBypassCache be true if job’s force bypass cache flag is
  //     set, and false otherwise.
  bool force_bypass_cache = state->job->force_bypass_cache_flag;
  // 16. Let runResult be the result of running the Run Service Worker
  //     algorithm with worker and forceBypassCache.
  auto* run_result = service_worker_context_->RunServiceWorker(
      worker.get(), force_bypass_cache);
  bool run_result_is_success = run_result;

  // Post a task for the remaining steps, to let tasks posted by
  // RunServiceWorker, such as for registering the web context, execute first.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&ServiceWorkerJobs::UpdateOnRunServiceWorker,
                            base::Unretained(this), std::move(state),
                            std::move(worker), run_result_is_success));
}

void ServiceWorkerJobs::UpdateOnRunServiceWorker(
    scoped_refptr<UpdateJobState> state,
    scoped_refptr<ServiceWorkerObject> worker, bool run_result) {
  // 17. If runResult is failure or an abrupt completion, then:
  if (!run_result) {
    // 17.1. Invoke Reject Job Promise with job and TypeError.
    RejectJobPromise(state->job, PromiseErrorData(script::kSimpleTypeError));
    // 17.2. If newestWorker is null, then remove registration
    //       map[(registration’s storage key, serialized scopeURL)].
    if (state->newest_worker == nullptr) {
      service_worker_context_->registration_map()->RemoveRegistration(
          state->job->storage_key, state->job->scope_url);
    }
    // 17.3. Invoke Finish Job with job.
    FinishJob(state->job);
  } else {
    // 18. Else, invoke Install algorithm with job, worker, and registration
    //     as its arguments.
    Install(state->job, std::move(worker), state->registration);
  }
}

void ServiceWorkerJobs::Install(
    Job* job, const scoped_refptr<ServiceWorkerObject>& worker,
    const scoped_refptr<ServiceWorkerRegistrationObject>& registration) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::Install()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Algorithm for Install:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#installation-algorithm

  // 1. Let installFailed be false.
  // Using a shared pointer because this flag is explicitly defined in the spec
  // to be modified from the worker's event loop, at asynchronous promise
  // completion that may occur after a timeout.
  std::shared_ptr<starboard::atomic_bool> install_failed(
      new starboard::atomic_bool(false));

  // 2. Let newestWorker be the result of running Get Newest Worker algorithm
  //    passing registration as its argument.
  const scoped_refptr<ServiceWorkerObject>& newest_worker =
      registration->GetNewestWorker();

  // 3. Set registration’s update via cache mode to job’s update via cache mode.
  registration->set_update_via_cache_mode(job->update_via_cache);

  // 4. Run the Update Registration State algorithm passing registration,
  //    "installing" and worker as the arguments.
  service_worker_context_->UpdateRegistrationState(
      registration, ServiceWorkerContext::kInstalling, worker);

  // 5. Run the Update Worker State algorithm passing registration’s installing
  //    worker and "installing" as the arguments.
  service_worker_context_->UpdateWorkerState(registration->installing_worker(),
                                             kServiceWorkerStateInstalling);
  // 6. Assert: job’s job promise is not null.
  DCHECK(job->no_promise_okay || job->promise.get() != nullptr);
  // 7. Invoke Resolve Job Promise with job and registration.
  ResolveJobPromise(job, registration);
  // 8. Let settingsObjects be all environment settings objects whose origin is
  //    registration’s scope url's origin.
  auto registration_origin = loader::Origin(registration->scope_url());
  // 9. For each settingsObject of settingsObjects...
  for (auto& context : service_worker_context_->web_context_registrations()) {
    if (context->environment_settings()->GetOrigin() == registration_origin) {
      // 9. ... queue a task on settingsObject’s responsible event loop in the
      //    DOM manipulation task source to run the following steps:
      context->message_loop()->task_runner()->PostBlockingTask(
          FROM_HERE,
          base::Bind(
              [](web::Context* context,
                 scoped_refptr<ServiceWorkerRegistrationObject> registration) {
                // 9.1. Let registrationObjects be every
                //      ServiceWorkerRegistration object in settingsObject’s
                //      realm, whose service worker registration is
                //      registration.

                // There is at most one per web context, stored in the service
                // worker registration object map of the web context.

                // 9.2. For each registrationObject of registrationObjects, fire
                //      an event on registrationObject named updatefound.
                auto registration_object =
                    context->LookupServiceWorkerRegistration(registration);
                if (registration_object) {
                  context->message_loop()->task_runner()->PostTask(
                      FROM_HERE,
                      base::BindOnce(
                          [](scoped_refptr<ServiceWorkerRegistration>
                                 registration_object) {
                            registration_object->DispatchEvent(
                                new web::Event(base::Tokens::updatefound()));
                          },
                          registration_object));
                }
              },
              context, registration));
    }
  }
  // 10. Let installingWorker be registration’s installing worker.
  ServiceWorkerObject* installing_worker = registration->installing_worker();
  // 11. If the result of running the Should Skip Event algorithm with
  //     installingWorker and "install" is false, then:
  if (!installing_worker->ShouldSkipEvent(base::Tokens::install())) {
    // 11.1. Let forceBypassCache be true if job’s force bypass cache flag is
    //       set, and false otherwise.
    bool force_bypass_cache = job->force_bypass_cache_flag;
    // 11.2. If the result of running the Run Service Worker algorithm with
    //       installingWorker and forceBypassCache is failure, then:
    auto* run_result = service_worker_context_->RunServiceWorker(
        installing_worker, force_bypass_cache);
    if (!run_result) {
      // 11.2.1. Set installFailed to true.
      install_failed->store(true);
      // 11.3. Else:
    } else {
      // 11.3.1. Queue a task task on installingWorker’s event loop using the
      //         DOM manipulation task source to run the following steps:
      DCHECK(registration->done_event()->IsSignaled());
      registration->done_event()->Reset();
      installing_worker->web_agent()
          ->context()
          ->message_loop()
          ->task_runner()
          ->PostBlockingTask(
              FROM_HERE,
              base::Bind(
                  [](ServiceWorkerObject* installing_worker,
                     base::WaitableEvent* done_event,
                     std::shared_ptr<starboard::atomic_bool> install_failed) {
                    // 11.3.1.1. Let e be the result of creating an event with
                    //           ExtendableEvent.
                    // 11.3.1.2. Initialize e’s type attribute to install.
                    // 11.3.1.3. Dispatch e at installingWorker’s global object.
                    // 11.3.1.4. WaitForAsynchronousExtensions: Run the
                    //           following substeps in parallel:
                    // 11.3.1.4.1. Wait until e is not active.
                    // 11.3.1.4.2. If e’s timed out flag is set, set
                    //             installFailed to true.
                    // 11.3.1.4.3. Let p be the result of getting a promise to
                    //             wait for all of e’s extend lifetime promises.
                    // 11.3.1.4.4. Upon rejection of p, set installFailed to
                    //             true.
                    //         If task is discarded, set installFailed to true.
                    auto done_callback = base::BindOnce(
                        [](base::WaitableEvent* done_event,
                           std::shared_ptr<starboard::atomic_bool>
                               install_failed,
                           bool was_rejected) {
                          if (was_rejected) install_failed->store(true);
                          done_event->Signal();
                        },
                        done_event, install_failed);
                    auto* settings = installing_worker->web_agent()
                                         ->context()
                                         ->environment_settings();
                    scoped_refptr<ExtendableEvent> event(
                        new ExtendableEvent(settings, base::Tokens::install(),
                                            std::move(done_callback)));
                    installing_worker->worker_global_scope()->DispatchEvent(
                        event);
                    if (!event->IsActive()) {
                      // If the event handler doesn't use waitUntil(), it will
                      // already no longer be active, and there will never be a
                      // callback to signal the done event.
                      done_event->Signal();
                    }
                  },
                  base::Unretained(installing_worker),
                  registration->done_event(), install_failed));
      // 11.3.2. Wait for task to have executed or been discarded.
      // This waiting is done inside PostBlockingTask above.
      // 11.3.3. Wait for the step labeled WaitForAsynchronousExtensions to
      //         complete.
      if (!service_worker_context_->WaitForAsynchronousExtensions(
              registration)) {
        // Timeout
        install_failed->store(true);
      }
    }
  }
  // 12. If installFailed is true, then:
  if (install_failed->load() || !registration->installing_worker()) {
    // 12.1. Run the Update Worker State algorithm passing registration’s
    //       installing worker and "redundant" as the arguments.
    if (registration->installing_worker()) {
      service_worker_context_->UpdateWorkerState(
          registration->installing_worker(), kServiceWorkerStateRedundant);
    }
    // 12.2. Run the Update Registration State algorithm passing registration,
    //       "installing" and null as the arguments.
    service_worker_context_->UpdateRegistrationState(
        registration, ServiceWorkerContext::kInstalling, nullptr);
    // 12.3. If newestWorker is null, then remove registration
    //       map[(registration’s storage key, serialized registration’s
    //       scope url)].
    if (newest_worker == nullptr) {
      service_worker_context_->registration_map()->RemoveRegistration(
          registration->storage_key(), registration->scope_url());
    }
    // 12.4. Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }
  // 13. Let map be registration’s installing worker's script resource map.
  // 14. Let usedSet be registration’s installing worker's set of used scripts.
  // 15. For each url of map:
  // 15.1. If usedSet does not contain url, then remove map[url].
  registration->installing_worker()->PurgeScriptResourceMap();

  // 16. If registration’s waiting worker is not null, then:
  if (registration->waiting_worker()) {
    // 16.1. Terminate registration’s waiting worker.
    service_worker_context_->TerminateServiceWorker(
        registration->waiting_worker());
    // 16.2. Run the Update Worker State algorithm passing registration’s
    //       waiting worker and "redundant" as the arguments.
    service_worker_context_->UpdateWorkerState(registration->waiting_worker(),
                                               kServiceWorkerStateRedundant);
  }
  // 17. Run the Update Registration State algorithm passing registration,
  //     "waiting" and registration’s installing worker as the arguments.
  service_worker_context_->UpdateRegistrationState(
      registration, ServiceWorkerContext::kWaiting,
      registration->installing_worker());
  // 18. Run the Update Registration State algorithm passing registration,
  //     "installing" and null as the arguments.
  service_worker_context_->UpdateRegistrationState(
      registration, ServiceWorkerContext::kInstalling, nullptr);
  // 19. Run the Update Worker State algorithm passing registration’s waiting
  //     worker and "installed" as the arguments.
  service_worker_context_->UpdateWorkerState(registration->waiting_worker(),
                                             kServiceWorkerStateInstalled);
  // 20. Invoke Finish Job with job.
  FinishJob(job);
  // 21. Wait for all the tasks queued by Update Worker State invoked in this
  //     algorithm to have executed.
  // TODO(b/234788479): Wait for tasks.
  // 22. Invoke Try Activate with registration.
  service_worker_context_->TryActivate(registration);

  // Persist registration since the waiting_worker has been updated.
  service_worker_context_->registration_map()->PersistRegistration(
      registration->storage_key(), registration->scope_url());
}

void ServiceWorkerJobs::Unregister(Job* job) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::Unregister()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Algorithm for Unregister:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#unregister-algorithm
  // 1. If the origin of job’s scope url is not job’s client's origin, then:
  if (job->client &&
      !url::Origin::Create(GURL(job->client->environment_settings()
                                    ->GetOrigin()
                                    .SerializedOrigin()))
           .IsSameOriginWith(url::Origin::Create(job->scope_url))) {
    // 1.1. Invoke Reject Job Promise with job and "SecurityError" DOMException.
    RejectJobPromise(
        job,
        PromiseErrorData(web::DOMException::kSecurityErr,
                         ServiceWorkerConsts::
                             kServiceWorkerUnregisterScopeOriginNotSameError));

    // 1.2. Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }

  // 2. Let registration be the result of running Get Registration given job’s
  //    storage key and job’s scope url.
  scoped_refptr<ServiceWorkerRegistrationObject> registration =
      service_worker_context_->registration_map()->GetRegistration(
          job->storage_key, job->scope_url);

  // 3. If registration is null, then:
  if (!registration) {
    // 3.1. Invoke Resolve Job Promise with job and false.
    ResolveJobPromise(job, false);

    // 3.2. Invoke Finish Job with job and abort these steps.
    FinishJob(job);
    return;
  }

  // 4. Remove registration map[(registration’s storage key, job’s scope url)].
  // Keep the registration until this algorithm finishes.
  service_worker_context_->registration_map()->RemoveRegistration(
      registration->storage_key(), job->scope_url);

  // 5. Invoke Resolve Job Promise with job and true.
  ResolveJobPromise(job, true);

  // 6. Invoke Try Clear Registration with registration.
  service_worker_context_->TryClearRegistration(registration);

  // 7. Invoke Finish Job with job.
  FinishJob(job);
}

void ServiceWorkerJobs::RejectJobPromise(Job* job,
                                         const PromiseErrorData& error_data) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::RejectJobPromise()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Algorithm for Reject Job Promise:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#reject-job-promise
  base::AutoLock lock(job->equivalent_jobs_promise_mutex);
  // 1. If job’s client is not null, queue a task, on job’s client's responsible
  //    event loop using the DOM manipulation task source, to reject job’s job
  //    promise with a new exception with errorData and a user agent-defined
  //    message, in job’s client's Realm.
  // 2.1. If equivalentJob’s client is null, continue.
  // 2.2. Queue a task, on equivalentJob’s client's responsible event loop
  //      using the DOM manipulation task source, to reject equivalentJob’s
  //      job promise with a new exception with errorData and a user
  //      agent-defined message, in equivalentJob’s client's Realm.
  if (job->client && job->promise != nullptr) {
    DCHECK(service_worker_context_->IsWebContextRegistered(job->client));
    job->client->message_loop()->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(
                       [](std::unique_ptr<JobPromiseType> promise,
                          const PromiseErrorData& error_data) {
                         error_data.Reject(std::move(promise));
                       },
                       std::move(job->promise), error_data));
    // Ensure that the promise is cleared, so that equivalent jobs won't get
    // added from this point on.
    CHECK(!job->promise);
  }
  // 2. For each equivalentJob in job’s list of equivalent jobs:
  for (auto& equivalent_job : job->equivalent_jobs) {
    // Recurse for the equivalent jobs.
    RejectJobPromise(equivalent_job.get(), error_data);
  }
  job->equivalent_jobs.clear();
}

void ServiceWorkerJobs::ResolveJobPromise(
    Job* job, bool value,
    const scoped_refptr<ServiceWorkerRegistrationObject>& registration) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::ResolveJobPromise()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  DCHECK(job);
  // Algorithm for Resolve Job Promise:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#resolve-job-promise-algorithm
  base::AutoLock lock(job->equivalent_jobs_promise_mutex);
  // 1. If job’s client is not null, queue a task, on job’s client's responsible
  //    event loop using the DOM manipulation task source, to run the following
  //    substeps:
  // 2.1 If equivalentJob’s client is null, continue to the next iteration of
  // the loop.
  if (job->client && job->promise != nullptr) {
    DCHECK(service_worker_context_->IsWebContextRegistered(job->client));
    job->client->message_loop()->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](JobType type, web::Context* client,
               std::unique_ptr<JobPromiseType> promise, bool value,
               scoped_refptr<ServiceWorkerRegistrationObject> registration) {
              TRACE_EVENT0(
                  "cobalt::worker",
                  "ServiceWorkerJobs::ResolveJobPromise() ResolveTask");
              // 1.1./2.2.1. Let convertedValue be null.
              // 1.2./2.2.2. If job’s job type is either register or update, set
              //             convertedValue to the result of getting the service
              //             worker registration object that represents value in
              //             job’s client.
              if (type == kRegister || type == kUpdate) {
                scoped_refptr<cobalt::script::Wrappable> converted_value =
                    client->GetServiceWorkerRegistration(registration);
                // 1.4./2.2.4. Resolve job’s job promise with convertedValue.
                promise->Resolve(converted_value);
              } else {
                DCHECK_EQ(kUnregister, type);
                // 1.3./2.2.3. Else, set convertedValue to value, in job’s
                // client's
                //             Realm.
                bool converted_value = value;
                // 1.4./2.2.4. Resolve job’s job promise with convertedValue.
                promise->Resolve(converted_value);
              }
            },
            job->type, job->client, std::move(job->promise), value,
            registration));
    // Ensure that the promise is cleared, so that equivalent jobs won't get
    // added from this point on.
    CHECK(!job->promise);
  }

  // 2. For each equivalentJob in job’s list of equivalent jobs:
  for (auto& equivalent_job : job->equivalent_jobs) {
    // Recurse for the equivalent jobs.
    ResolveJobPromise(equivalent_job.get(), value, registration);
  }
  job->equivalent_jobs.clear();
}

// https://www.w3.org/TR/2022/CRD-service-workers-20220712/#finish-job-algorithm
void ServiceWorkerJobs::FinishJob(Job* job) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::FinishJob()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // 1. Let jobQueue be job’s containing job queue.
  JobQueue* job_queue = job->containing_job_queue;

  // 2. Assert: the first item in jobQueue is job.
  DCHECK_EQ(job, job_queue->FirstItem());

  // 3. Dequeue from jobQueue.
  job_queue->Dequeue();

  // 4. If jobQueue is not empty, invoke Run Job with jobQueue.
  if (!job_queue->empty()) {
    RunJob(job_queue);
  }
}

<<<<<<< HEAD
void ServiceWorkerJobs::MaybeResolveReadyPromiseSubSteps(web::Context* client) {
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Algorithm for Sub steps of ServiceWorkerContainer.ready():
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#navigator-service-worker-ready

  //    3.1. Let client by this's service worker client.
  //    3.2. Let storage key be the result of running obtain a storage
  //         key given client.
  url::Origin storage_key = client->environment_settings()->ObtainStorageKey();
  //    3.3. Let registration be the result of running Match Service
  //         Worker Registration given storage key and client’s
  //         creation URL.
  // TODO(b/234659851): Investigate whether this should use the creation URL
  // directly instead.
  const GURL& base_url = client->environment_settings()->creation_url();
  GURL client_url = base_url.Resolve("");
  scoped_refptr<ServiceWorkerRegistrationObject> registration =
      scope_to_registration_map_->MatchServiceWorkerRegistration(storage_key,
                                                                 client_url);
  //    3.3. If registration is not null, and registration’s active
  //         worker is not null, queue a task on readyPromise’s
  //         relevant settings object's responsible event loop, using
  //         the DOM manipulation task source, to resolve readyPromise
  //         with the result of getting the service worker
  //         registration object that represents registration in
  //         readyPromise’s relevant settings object.
  if (registration && registration->active_worker()) {
    client->message_loop()->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&ServiceWorkerContainer::MaybeResolveReadyPromise,
                       base::Unretained(client->GetWindowOrWorkerGlobalScope()
                                            ->navigator_base()
                                            ->service_worker()
                                            .get()),
                       registration));
  }
}

void ServiceWorkerJobs::GetRegistrationSubSteps(
    const url::Origin& storage_key, const GURL& client_url,
    web::Context* client,
    std::unique_ptr<script::ValuePromiseWrappable::Reference>
        promise_reference) {
  TRACE_EVENT0("cobalt::worker",
               "ServiceWorkerJobs::GetRegistrationSubSteps()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Algorithm for Sub steps of ServiceWorkerContainer.getRegistration():
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#navigator-service-worker-getRegistration

  // 8.1. Let registration be the result of running Match Service Worker
  //      Registration algorithm with clientURL as its argument.
  scoped_refptr<ServiceWorkerRegistrationObject> registration =
      scope_to_registration_map_->MatchServiceWorkerRegistration(storage_key,
                                                                 client_url);
  // 8.2. If registration is null, resolve promise with undefined and abort
  //      these steps.
  // 8.3. Resolve promise with the result of getting the service worker
  //      registration object that represents registration in promise’s
  //      relevant settings object.
  client->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](web::Context* client,
             std::unique_ptr<script::ValuePromiseWrappable::Reference> promise,
             scoped_refptr<ServiceWorkerRegistrationObject> registration) {
            TRACE_EVENT0(
                "cobalt::worker",
                "ServiceWorkerJobs::GetRegistrationSubSteps() Resolve");
            promise->value().Resolve(
                client->GetServiceWorkerRegistration(registration));
          },
          client, std::move(promise_reference), registration));
}

void ServiceWorkerJobs::GetRegistrationsSubSteps(
    const url::Origin& storage_key, web::Context* client,
    std::unique_ptr<script::ValuePromiseSequenceWrappable::Reference>
        promise_reference) {
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  std::vector<scoped_refptr<ServiceWorkerRegistrationObject>>
      registration_objects =
          scope_to_registration_map_->GetRegistrations(storage_key);
  client->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](web::Context* client,
             std::unique_ptr<script::ValuePromiseSequenceWrappable::Reference>
                 promise,
             std::vector<scoped_refptr<ServiceWorkerRegistrationObject>>
                 registration_objects) {
            TRACE_EVENT0(
                "cobalt::worker",
                "ServiceWorkerJobs::GetRegistrationSubSteps() Resolve");
            script::Sequence<scoped_refptr<script::Wrappable>> registrations;
            for (auto registration_object : registration_objects) {
              registrations.push_back(scoped_refptr<script::Wrappable>(
                  client->GetServiceWorkerRegistration(registration_object)
                      .get()));
            }
            promise->value().Resolve(std::move(registrations));
          },
          client, std::move(promise_reference),
          std::move(registration_objects)));
}

void ServiceWorkerJobs::SkipWaitingSubSteps(
    web::Context* worker_context, ServiceWorkerObject* service_worker,
    std::unique_ptr<script::ValuePromiseVoid::Reference> promise_reference) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::SkipWaitingSubSteps()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Check if the client web context is still active. This may trigger if
  // skipWaiting() was called and service worker installation fails.
  if (!IsWebContextRegistered(worker_context)) {
    promise_reference.release();
    return;
  }

  // Algorithm for Sub steps of ServiceWorkerGlobalScope.skipWaiting():
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#dom-serviceworkerglobalscope-skipwaiting

  // 2.1. Set service worker's skip waiting flag.
  service_worker->set_skip_waiting();

  // 2.2. Invoke Try Activate with service worker's containing service worker
  // registration.
  TryActivate(service_worker->containing_service_worker_registration());

  // 2.3. Resolve promise with undefined.
  worker_context->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](std::unique_ptr<script::ValuePromiseVoid::Reference> promise) {
            promise->value().Resolve();
          },
          std::move(promise_reference)));
}

void ServiceWorkerJobs::WaitUntilSubSteps(
    ServiceWorkerRegistrationObject* registration) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::WaitUntilSubSteps()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Sub steps for WaitUntil.
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#dom-extendableevent-waituntil
  // 5.2.2. If registration is unregistered, invoke Try Clear Registration
  //        with registration.
  if (scope_to_registration_map_->IsUnregistered(registration)) {
    TryClearRegistration(registration);
  }
  // 5.2.3. If registration is not null, invoke Try Activate with
  //        registration.
  if (registration) {
    TryActivate(registration);
  }
}

void ServiceWorkerJobs::ClientsGetSubSteps(
    web::Context* worker_context,
    ServiceWorkerObject* associated_service_worker,
    std::unique_ptr<script::ValuePromiseWrappable::Reference> promise_reference,
    const std::string& id) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::ClientsGetSubSteps()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Check if the client web context is still active. This may trigger if
  // Clients.get() was called and service worker installation fails.
  if (!IsWebContextRegistered(worker_context)) {
    promise_reference.release();
    return;
  }
  // Parallel sub steps (2) for algorithm for Clients.get(id):
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#clients-get
  // 2.1. For each service worker client client where the result of running
  //      obtain a storage key given client equals the associated service
  //      worker's containing service worker registration's storage key:
  const url::Origin& storage_key =
      associated_service_worker->containing_service_worker_registration()
          ->storage_key();
  for (auto& client : web_context_registrations_) {
    url::Origin client_storage_key =
        client->environment_settings()->ObtainStorageKey();
    if (client_storage_key.IsSameOriginWith(storage_key)) {
      // 2.1.1. If client’s id is not id, continue.
      if (client->environment_settings()->id() != id) continue;

      // 2.1.2. Wait for either client’s execution ready flag to be set or for
      //        client’s discarded flag to be set.
      // Web Contexts exist only in the web_context_registrations_ set when they
      // are both execution ready and not discarded.

      // 2.1.3. If client’s execution ready flag is set, then invoke Resolve Get
      //        Client Promise with client and promise, and abort these steps.
      ResolveGetClientPromise(client, worker_context,
                              std::move(promise_reference));
      return;
    }
  }
  // 2.2. Resolve promise with undefined.
  worker_context->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](std::unique_ptr<script::ValuePromiseWrappable::Reference>
                 promise_reference) {
            TRACE_EVENT0("cobalt::worker",
                         "ServiceWorkerJobs::ClientsGetSubSteps() Resolve");
            promise_reference->value().Resolve(scoped_refptr<Client>());
          },
          std::move(promise_reference)));
}

void ServiceWorkerJobs::ResolveGetClientPromise(
    web::Context* client, web::Context* worker_context,
    std::unique_ptr<script::ValuePromiseWrappable::Reference>
        promise_reference) {
  TRACE_EVENT0("cobalt::worker",
               "ServiceWorkerJobs::ResolveGetClientPromise()");
  // Algorithm for Resolve Get Client Promise:
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#resolve-get-client-promise

  // 1. If client is an environment settings object, then:
  // 1.1. If client is not a secure context, queue a task to reject promise with
  //      a "SecurityError" DOMException, on promise’s relevant settings
  //      object's responsible event loop using the DOM manipulation task
  //      source, and abort these steps.
  // 2. Else:
  // 2.1. If client’s creation URL is not a potentially trustworthy URL, queue
  //      a task to reject promise with a "SecurityError" DOMException, on
  //      promise’s relevant settings object's responsible event loop using the
  //      DOM manipulation task source, and abort these steps.
  // In production, Cobalt requires https, therefore all clients are secure
  // contexts.

  // 3. If client is an environment settings object and is not a window client,
  //    then:
  if (!client->GetWindowOrWorkerGlobalScope()->IsWindow()) {
    // 3.1. Let clientObject be the result of running Create Client algorithm
    //      with client as the argument.
    scoped_refptr<Client> client_object =
        Client::Create(client->environment_settings());

    // 3.2. Queue a task to resolve promise with clientObject, on promise’s
    //      relevant settings object's responsible event loop using the DOM
    //      manipulation task source, and abort these steps.
    worker_context->message_loop()->task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            [](std::unique_ptr<script::ValuePromiseWrappable::Reference>
                   promise_reference,
               scoped_refptr<Client> client_object) {
              TRACE_EVENT0(
                  "cobalt::worker",
                  "ServiceWorkerJobs::ResolveGetClientPromise() Resolve");
              promise_reference->value().Resolve(client_object);
            },
            std::move(promise_reference), client_object));
    return;
  }
  // 4. Else:
  // 4.1. Let browsingContext be null.
  // 4.2. If client is an environment settings object, set browsingContext to
  //      client’s global object's browsing context.
  // 4.3. Else, set browsingContext to client’s target browsing context.
  // Note: Cobalt does not implement a distinction between environments and
  // environment settings objects.
  // 4.4. Queue a task to run the following steps on browsingContext’s event
  //      loop using the user interaction task source:
  // Note: The task below does not currently perform any actual
  // functionality in the client context. It is included however to help future
  // implementation for fetching values for WindowClient properties, with
  // similar logic existing in ClientsMatchAllSubSteps.
  client->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](web::Context* client, web::Context* worker_context,
             std::unique_ptr<script::ValuePromiseWrappable::Reference>
                 promise_reference) {
            // 4.4.1. Let frameType be the result of running Get Frame Type with
            //        browsingContext.
            // Cobalt does not support nested or auxiliary browsing contexts.
            // 4.4.2. Let visibilityState be browsingContext’s active document's
            //        visibilityState attribute value.
            // 4.4.3. Let focusState be the result of running the has focus
            //        steps with browsingContext’s active document as the
            //        argument.
            // Handled in the WindowData constructor.
            std::unique_ptr<WindowData> window_data(
                new WindowData(client->environment_settings()));

            // 4.4.4. Let ancestorOriginsList be the empty list.
            // 4.4.5. If client is a window client, set ancestorOriginsList to
            //        browsingContext’s active document's relevant global
            //        object's Location object’s ancestor origins list's
            //        associated list.
            // Cobalt does not implement Location.ancestorOrigins.

            // 4.4.6. Queue a task to run the following steps on promise’s
            //        relevant settings object's responsible event loop using
            //        the DOM manipulation task source:
            worker_context->message_loop()->task_runner()->PostTask(
                FROM_HERE,
                base::BindOnce(
                    [](std::unique_ptr<script::ValuePromiseWrappable::Reference>
                           promise_reference,
                       std::unique_ptr<WindowData> window_data) {
                      // 4.4.6.1. If client’s discarded flag is set, resolve
                      //          promise with undefined and abort these
                      //          steps.
                      // 4.4.6.2. Let windowClient be the result of running
                      //          Create Window Client with client,
                      //          frameType, visibilityState, focusState,
                      //          and ancestorOriginsList.
                      scoped_refptr<Client> window_client =
                          WindowClient::Create(*window_data);
                      // 4.4.6.3. Resolve promise with windowClient.
                      promise_reference->value().Resolve(window_client);
                    },
                    std::move(promise_reference), std::move(window_data)));
          },
          client, worker_context, std::move(promise_reference)));
  DCHECK_EQ(nullptr, promise_reference.get());
}

void ServiceWorkerJobs::ClientsMatchAllSubSteps(
    web::Context* worker_context,
    ServiceWorkerObject* associated_service_worker,
    std::unique_ptr<script::ValuePromiseSequenceWrappable::Reference>
        promise_reference,
    bool include_uncontrolled, ClientType type) {
  TRACE_EVENT0("cobalt::worker",
               "ServiceWorkerJobs::ClientsMatchAllSubSteps()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  // Check if the worker web context is still active. This may trigger if
  // Clients.matchAll() was called and service worker installation fails.
  if (!IsWebContextRegistered(worker_context)) {
    promise_reference.release();
    return;
  }

  // Parallel sub steps (2) for algorithm for Clients.matchAll():
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#clients-matchall
  // 2.1. Let targetClients be a new list.
  std::list<web::Context*> target_clients;

  // 2.2. For each service worker client client where the result of running
  //      obtain a storage key given client equals the associated service
  //      worker's containing service worker registration's storage key:
  const url::Origin& storage_key =
      associated_service_worker->containing_service_worker_registration()
          ->storage_key();
  for (auto& client : web_context_registrations_) {
    url::Origin client_storage_key =
        client->environment_settings()->ObtainStorageKey();
    if (client_storage_key.IsSameOriginWith(storage_key)) {
      // 2.2.1. If client’s execution ready flag is unset or client’s discarded
      //        flag is set, continue.
      // Web Contexts exist only in the web_context_registrations_ set when they
      // are both execution ready and not discarded.

      // 2.2.2. If client is not a secure context, continue.
      // In production, Cobalt requires https, therefore all workers and their
      // owners are secure contexts.

      // 2.2.3. If options["includeUncontrolled"] is false, and if client’s
      //        active service worker is not the associated service worker,
      //        continue.
      if (!include_uncontrolled &&
          (client->active_service_worker() != associated_service_worker)) {
        continue;
      }

      // 2.2.4. Add client to targetClients.
      target_clients.push_back(client);
    }
  }

  // 2.3. Let matchedWindowData be a new list.
  std::unique_ptr<std::vector<WindowData>> matched_window_data(
      new std::vector<WindowData>);

  // 2.4. Let matchedClients be a new list.
  std::unique_ptr<std::vector<web::Context*>> matched_clients(
      new std::vector<web::Context*>);

  // 2.5. For each service worker client client in targetClients:
  for (auto* client : target_clients) {
    auto* global_scope = client->GetWindowOrWorkerGlobalScope();

    if ((type == kClientTypeWindow || type == kClientTypeAll) &&
        (global_scope->IsWindow())) {
      // 2.5.1. If options["type"] is "window" or "all", and client is not an
      //        environment settings object or is a window client, then:

      // 2.5.1.1. Let windowData be [ "client" -> client, "ancestorOriginsList"
      //          -> a new list ].
      WindowData window_data(client->environment_settings());

      // 2.5.1.2. Let browsingContext be null.

      // 2.5.1.3. Let isClientEnumerable be true.
      // For Cobalt, isClientEnumerable is always true because the clauses that
      // would set it to false in 2.5.1.6. do not apply to Cobalt.

      // 2.5.1.4. If client is an environment settings object, set
      //          browsingContext to client’s global object's browsing context.
      // 2.5.1.5. Else, set browsingContext to client’s target browsing context.
      web::Context* browsing_context = client;

      // 2.5.1.6. Queue a task task to run the following substeps on
      //          browsingContext’s event loop using the user interaction task
      //          source:
      // Note: The task below does not currently perform any actual
      // functionality. It is included however to help future implementation for
      // fetching values for WindowClient properties, with similar logic
      // existing in ResolveGetClientPromise.
      browsing_context->message_loop()->task_runner()->PostBlockingTask(
          FROM_HERE, base::Bind(
                         [](WindowData* window_data) {
                           // 2.5.1.6.1. If browsingContext has been discarded,
                           //            then set isClientEnumerable to false
                           //            and abort these steps.
                           // 2.5.1.6.2. If client is a window client and
                           //            client’s responsible document is not
                           //            browsingContext’s active document, then
                           //            set isClientEnumerable to false and
                           //            abort these steps.
                           // In Cobalt, the document of a window browsing
                           // context doesn't change: When a new document is
                           // created, a new browsing context is created with
                           // it.

                           // 2.5.1.6.3. Set windowData["frameType"] to the
                           //            result of running Get Frame Type with
                           //            browsingContext.
                           // Cobalt does not support nested or auxiliary
                           // browsing contexts.
                           // 2.5.1.6.4. Set windowData["visibilityState"] to
                           //            browsingContext’s active document's
                           //            visibilityState attribute value.
                           // 2.5.1.6.5. Set windowData["focusState"] to the
                           //            result of running the has focus steps
                           //            with browsingContext’s active document
                           //            as the argument.

                           // 2.5.1.6.6. If client is a window client, then set
                           //            windowData["ancestorOriginsList"] to
                           //            browsingContext’s active document's
                           //            relevant global object's Location
                           //            object’s ancestor origins list's
                           //            associated list.
                           // Cobalt does not implement
                           // Location.ancestorOrigins.
                         },
                         &window_data));

      // 2.5.1.7. Wait for task to have executed.
      // The task above is posted as a blocking task.

      // 2.5.1.8. If isClientEnumerable is true, then:

      // 2.5.1.8.1. Add windowData to matchedWindowData.
      matched_window_data->emplace_back(window_data);

      // 2.5.2. Else if options["type"] is "worker" or "all" and client is a
      //        dedicated worker client, or options["type"] is "sharedworker" or
      //        "all" and client is a shared worker client, then:
    } else if (((type == kClientTypeWorker || type == kClientTypeAll) &&
                global_scope->IsDedicatedWorker())) {
      // Note: Cobalt does not support shared workers.
      // 2.5.2.1. Add client to matchedClients.
      matched_clients->emplace_back(client);
    }
  }

  // 2.6. Queue a task to run the following steps on promise’s relevant
  // settings object's responsible event loop using the DOM manipulation
  // task source:
  worker_context->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](std::unique_ptr<script::ValuePromiseSequenceWrappable::Reference>
                 promise_reference,
             std::unique_ptr<std::vector<WindowData>> matched_window_data,
             std::unique_ptr<std::vector<web::Context*>> matched_clients) {
            TRACE_EVENT0(
                "cobalt::worker",
                "ServiceWorkerJobs::ClientsMatchAllSubSteps() Resolve Promise");
            // 2.6.1. Let clientObjects be a new list.
            script::Sequence<scoped_refptr<script::Wrappable>> client_objects;

            // 2.6.2. For each windowData in matchedWindowData:
            for (auto& window_data : *matched_window_data) {
              // 2.6.2.1. Let WindowClient be the result of running
              //          Create Window Client algorithm with
              //          windowData["client"],
              //          windowData["frameType"],
              //          windowData["visibilityState"],
              //          windowData["focusState"], and
              //          windowData["ancestorOriginsList"] as the
              //          arguments.
              // TODO(b/235838698): Implement WindowClient methods.
              scoped_refptr<Client> window_client =
                  WindowClient::Create(window_data);

              // 2.6.2.2. Append WindowClient to clientObjects.
              client_objects.push_back(window_client);
            }

            // 2.6.3. For each client in matchedClients:
            for (auto& client : *matched_clients) {
              // 2.6.3.1. Let clientObject be the result of running
              //          Create Client algorithm with client as the
              //          argument.
              scoped_refptr<Client> client_object =
                  Client::Create(client->environment_settings());

              // 2.6.3.2. Append clientObject to clientObjects.
              client_objects.push_back(client_object);
            }
            // 2.6.4. Sort clientObjects such that:
            //        . WindowClient objects whose browsing context has been
            //          focused are placed first, sorted in the most recently
            //          focused order.
            //        . WindowClient objects whose browsing context has never
            //          been focused are placed next, sorted in their service
            //          worker client's creation order.
            //        . Client objects whose associated service worker client is
            //          a worker client are placed next, sorted in their service
            //          worker client's creation order.
            // TODO(b/235876598): Implement sorting of clientObjects.

            // 2.6.5. Resolve promise with a new frozen array of clientObjects
            //        in promise’s relevant Realm.
            promise_reference->value().Resolve(client_objects);
          },
          std::move(promise_reference), std::move(matched_window_data),
          std::move(matched_clients)));
}

void ServiceWorkerJobs::ClaimSubSteps(
    web::Context* worker_context,
    ServiceWorkerObject* associated_service_worker,
    std::unique_ptr<script::ValuePromiseVoid::Reference> promise_reference) {
  TRACE_EVENT0("cobalt::worker", "ServiceWorkerJobs::ClaimSubSteps()");
  DCHECK_EQ(message_loop(), base::MessageLoop::current());

  // Check if the client web context is still active. This may trigger if
  // Clients.claim() was called and service worker installation fails.
  if (!IsWebContextRegistered(worker_context)) {
    promise_reference.release();
    return;
  }

  // Parallel sub steps (3) for algorithm for Clients.claim():
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#dom-clients-claim
  std::list<web::Context*> target_clients;

  // 3.1. For each service worker client client where the result of running
  //      obtain a storage key given client equals the service worker's
  //      containing service worker registration's storage key:
  const url::Origin& storage_key =
      associated_service_worker->containing_service_worker_registration()
          ->storage_key();
  for (auto& client : web_context_registrations_) {
    // Don't claim to be our own service worker.
    if (client == worker_context) continue;
    url::Origin client_storage_key =
        client->environment_settings()->ObtainStorageKey();
    if (client_storage_key.IsSameOriginWith(storage_key)) {
      // 3.1.1. If client’s execution ready flag is unset or client’s discarded
      //        flag is set, continue.
      // Web Contexts exist only in the web_context_registrations_ set when they
      // are both execution ready and not discarded.

      // 3.1.2. If client is not a secure context, continue.
      // In production, Cobalt requires https, therefore all clients are secure
      // contexts.

      // 3.1.3. Let storage key be the result of running obtain a storage key
      //        given client.
      // 3.1.4. Let registration be the result of running Match Service Worker
      //        Registration given storage key and client’s creation URL.
      // TODO(b/234659851): Investigate whether this should use the creation
      // URL directly instead.
      const GURL& base_url = client->environment_settings()->creation_url();
      GURL client_url = base_url.Resolve("");
      scoped_refptr<ServiceWorkerRegistrationObject> registration =
          scope_to_registration_map_->MatchServiceWorkerRegistration(
              client_storage_key, client_url);

      // 3.1.5. If registration is not the service worker's containing service
      //        worker registration, continue.
      if (registration !=
          associated_service_worker->containing_service_worker_registration()) {
        continue;
      }

      // 3.1.6. If client’s active service worker is not the service worker,
      //        then:
      if (client->active_service_worker() != associated_service_worker) {
        // 3.1.6.1. Invoke Handle Service Worker Client Unload with client as
        //          the argument.
        HandleServiceWorkerClientUnload(client);

        // 3.1.6.2. Set client’s active service worker to service worker.
        client->set_active_service_worker(associated_service_worker);

        // 3.1.6.3. Invoke Notify Controller Change algorithm with client as the
        //          argument.
        NotifyControllerChange(client);
      }
    }
  }
  // 3.2. Resolve promise with undefined.
  worker_context->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](std::unique_ptr<script::ValuePromiseVoid::Reference> promise) {
            promise->value().Resolve();
          },
          std::move(promise_reference)));
}

void ServiceWorkerJobs::ServiceWorkerPostMessageSubSteps(
    ServiceWorkerObject* service_worker, web::Context* incumbent_client,
    std::unique_ptr<script::DataBuffer> serialize_result) {
  // Parallel sub steps (6) for algorithm for ServiceWorker.postMessage():
  //   https://www.w3.org/TR/2022/CRD-service-workers-20220712/#service-worker-postmessage-options
  // 3. Let incumbentGlobal be incumbentSettings’s global object.
  // Note: The 'incumbent' is the sender of the message.
  // 6.1 If the result of running the Run Service Worker algorithm with
  //     serviceWorker is failure, then return.
  auto* run_result = RunServiceWorker(service_worker);
  if (!run_result) return;
  if (!serialize_result) return;

  // 6.2 Queue a task on the DOM manipulation task source to run the following
  //     steps:
  incumbent_client->message_loop()->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](ServiceWorkerObject* service_worker,
             web::Context* incumbent_client,
             std::unique_ptr<script::DataBuffer> serialize_result) {
            if (!serialize_result) return;

            web::EventTarget* event_target =
                service_worker->worker_global_scope();
            if (!event_target) return;

            web::WindowOrWorkerGlobalScope* incumbent_global =
                incumbent_client->GetWindowOrWorkerGlobalScope();
            DCHECK_EQ(incumbent_client->environment_settings(),
                      incumbent_global->environment_settings());
            base::TypeId incumbent_type = incumbent_global->GetWrappableType();
            ServiceWorkerObject* incumbent_worker =
                incumbent_global->IsServiceWorker()
                    ? incumbent_global->AsServiceWorker()
                          ->service_worker_object()
                    : nullptr;
            base::MessageLoop* message_loop =
                event_target->environment_settings()->context()->message_loop();
            if (!message_loop) {
              return;
            }
            message_loop->task_runner()->PostTask(
                FROM_HERE,
                base::BindOnce(
                    [](const base::TypeId& incumbent_type,
                       ServiceWorkerObject* incumbent_worker,
                       web::Context* incumbent_client,
                       web::EventTarget* event_target,
                       std::unique_ptr<script::DataBuffer> serialize_result) {
                      ExtendableMessageEventInit init_dict;
                      if (incumbent_type ==
                          base::GetTypeId<ServiceWorkerGlobalScope>()) {
                        // 6.2.1. Let source be determined by switching on the
                        //        type of incumbentGlobal:
                        //        . ServiceWorkerGlobalScope
                        //          The result of getting the service worker
                        //          object that represents incumbentGlobal’s
                        //          service worker in the relevant settings
                        //          object of serviceWorker’s global object.
                        init_dict.set_source(ExtendableMessageEvent::SourceType(
                            event_target->environment_settings()
                                ->context()
                                ->GetServiceWorker(incumbent_worker)));
                      } else if (incumbent_type ==
                                 base::GetTypeId<dom::Window>()) {
                        //        . Window
                        //          a new WindowClient object that represents
                        //          incumbentGlobal’s relevant settings object.
                        init_dict.set_source(ExtendableMessageEvent::SourceType(
                            WindowClient::Create(WindowData(
                                incumbent_client->environment_settings()))));
                      } else {
                        //        . Otherwise
                        //          a new Client object that represents
                        //          incumbentGlobal’s associated worker
                        init_dict.set_source(
                            ExtendableMessageEvent::SourceType(Client::Create(
                                incumbent_client->environment_settings())));
                      }

                      event_target->DispatchEvent(
                          new worker::ExtendableMessageEvent(
                              event_target->environment_settings(),
                              base::Tokens::message(), init_dict,
                              std::move(serialize_result)));
                    },
                    incumbent_type, base::Unretained(incumbent_worker),
                    // Note: These should probably be weak pointers for when
                    // the message sender disappears before the recipient
                    // processes the event, but since base::WeakPtr
                    // dereferencing isn't thread-safe, that can't actually be
                    // used here.
                    base::Unretained(incumbent_client),
                    base::Unretained(event_target),
                    std::move(serialize_result)));
          },
          base::Unretained(service_worker), base::Unretained(incumbent_client),
          std::move(serialize_result)));
}

void ServiceWorkerJobs::RegisterWebContext(web::Context* context) {
  DCHECK_NE(nullptr, context);
  web_context_registrations_cleared_.Reset();
  if (base::MessageLoop::current() != message_loop()) {
    DCHECK(message_loop());
    message_loop()->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&ServiceWorkerJobs::RegisterWebContext,
                                  base::Unretained(this), context));
    return;
  }
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  DCHECK_EQ(0, web_context_registrations_.count(context));
  web_context_registrations_.insert(context);
}

void ServiceWorkerJobs::SetActiveWorker(web::EnvironmentSettings* client) {
  if (!client) return;
  if (base::MessageLoop::current() != message_loop()) {
    DCHECK(message_loop());
    message_loop()->task_runner()->PostTask(
        FROM_HERE, base::Bind(&ServiceWorkerJobs::SetActiveWorker,
                              base::Unretained(this), client));
    return;
  }
  DCHECK(scope_to_registration_map_);
  scoped_refptr<ServiceWorkerRegistrationObject> client_registration =
      scope_to_registration_map_->MatchServiceWorkerRegistration(
          client->ObtainStorageKey(), client->creation_url());
  if (client_registration.get() && client_registration->active_worker()) {
    client->context()->set_active_service_worker(
        client_registration->active_worker());
  } else {
    client->context()->set_active_service_worker(nullptr);
  }
}

void ServiceWorkerJobs::UnregisterWebContext(web::Context* context) {
  DCHECK_NE(nullptr, context);
  if (base::MessageLoop::current() != message_loop()) {
    // Block to ensure that the context is unregistered before it is destroyed.
    DCHECK(message_loop());
    message_loop()->task_runner()->PostBlockingTask(
        FROM_HERE, base::Bind(&ServiceWorkerJobs::UnregisterWebContext,
                              base::Unretained(this), context));
    return;
  }
  DCHECK_EQ(message_loop(), base::MessageLoop::current());
  DCHECK_EQ(1, web_context_registrations_.count(context));
  web_context_registrations_.erase(context);
  HandleServiceWorkerClientUnload(context);
  PrepareForClientShutdown(context);
  if (web_context_registrations_.empty()) {
    web_context_registrations_cleared_.Signal();
  }
}

=======
>>>>>>> 6e280c8f020 (Moving service worker job related code to its own file. (#628))
void ServiceWorkerJobs::PrepareForClientShutdown(web::Context* client) {
  DCHECK(client);
  if (!client) return;
  DCHECK(base::MessageLoop::current() == message_loop());
  // Note: This could be rewritten to use the decomposition declaration
  // 'const auto& [scope, queue]' after switching to C++17.
  for (const auto& entry : job_queue_map_) {
    const std::string& scope = entry.first;
    const std::unique_ptr<JobQueue>& queue = entry.second;
    DCHECK(queue.get());
    queue->PrepareForClientShutdown(client);
  }
}

void ServiceWorkerJobs::JobQueue::PrepareForClientShutdown(
    web::Context* client) {
  for (const auto& job : jobs_) {
    PrepareJobForClientShutdown(job, client);
  }
}

void ServiceWorkerJobs::JobQueue::PrepareJobForClientShutdown(
    const std::unique_ptr<Job>& job, web::Context* client) {
  DCHECK(job);
  if (!job) return;
  base::AutoLock lock(job->equivalent_jobs_promise_mutex);
  if (client == job->client) {
    job->promise.reset();
    job->client = nullptr;
  }
  for (const auto& equivalent_job : job->equivalent_jobs) {
    // Recurse for the equivalent jobs.
    PrepareJobForClientShutdown(equivalent_job, client);
  }
}

ServiceWorkerJobs::JobPromiseType::JobPromiseType(
    std::unique_ptr<script::ValuePromiseBool::Reference> promise_reference)
    : promise_bool_reference_(std::move(promise_reference)) {}
ServiceWorkerJobs::JobPromiseType::JobPromiseType(
    std::unique_ptr<script::ValuePromiseWrappable::Reference> promise_reference)
    : promise_wrappable_reference_(std::move(promise_reference)) {}

void ServiceWorkerJobs::JobPromiseType::Resolve(const bool result) {
  DCHECK(promise_bool_reference_);
  is_pending_.store(false);
  promise_bool_reference_->value().Resolve(result);
}

void ServiceWorkerJobs::JobPromiseType::Resolve(
    const scoped_refptr<cobalt::script::Wrappable>& result) {
  DCHECK(promise_wrappable_reference_);
  is_pending_.store(false);
  promise_wrappable_reference_->value().Resolve(result);
}

void ServiceWorkerJobs::JobPromiseType::Reject(
    script::SimpleExceptionType exception) {
  if (promise_bool_reference_) {
    is_pending_.store(false);
    promise_bool_reference_->value().Reject(exception);
    return;
  }
  if (promise_wrappable_reference_) {
    is_pending_.store(false);
    promise_wrappable_reference_->value().Reject(exception);
    return;
  }
  NOTREACHED();
}

void ServiceWorkerJobs::JobPromiseType::Reject(
    const scoped_refptr<script::ScriptException>& result) {
  if (promise_bool_reference_) {
    is_pending_.store(false);
    promise_bool_reference_->value().Reject(result);
    return;
  }
  if (promise_wrappable_reference_) {
    is_pending_.store(false);
    promise_wrappable_reference_->value().Reject(result);
    return;
  }
  NOTREACHED();
}

}  // namespace worker
}  // namespace cobalt
