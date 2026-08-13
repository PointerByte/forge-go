// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package jobs provides in-process scheduling for periodic and trigger-aligned
// background jobs.
//
// It exposes a process-wide scheduler through package-level helpers.
//
// Main entry points:
//   - Job and JobWithID to register fixed-interval work
//   - CronJob and CronJobWithID to register jobs aligned to a cron trigger
//   - StartJobs to start registered global jobs
//   - RestartJobs to restart them without clearing definitions
//   - PauseJob, ResumeJob, and StopJob to control jobs by id
//   - StopAllJobs to stop global jobs, optionally clearing them
//
// Jobs are not started when they are registered. They begin running only after
// StartJobs is called, and jobs added after startup begin executing
// immediately. RestartJobs is synchronous, preserves registered definitions,
// and is safe to call before StartJobs.
package jobs
