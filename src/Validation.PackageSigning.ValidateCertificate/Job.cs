// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NuGet.Jobs;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.ServiceBus;

namespace Validation.PackageSigning.ValidateCertificate
{
    internal class Job : JobBase
    {
        /// <summary>
        /// The maximum amount of time that graceful shutdown can take before the job will
        /// forcefully end itself.
        /// </summary>
        private static readonly TimeSpan MaxShutdownTime = TimeSpan.FromMinutes(1);

        /// <summary>
        /// How quickly the shutdown task should check its status.
        /// </summary>
        private static readonly TimeSpan ShutdownPollTime = TimeSpan.FromSeconds(1);

        private ISubscriptionProcessor<CertificateValidationMessage> _processor;
        private ILogger<Job> _logger;

        public override void Init(IDictionary<string, string> jobArgsDictionary)
        {
            // TODO: _processor
            // TODO: _logger
        }

        public async override Task Run()
        {
            _processor.Start();

            // Wait a day, and then shutdown this process so that it is recycled.
            await Task.Delay(TimeSpan.FromDays(1));
            await ShutdownAsync();
        }

        private async Task ShutdownAsync()
        {
            await _processor.StartShutdownAsync();

            // Wait until all certificate validations complete, or, the maximum shutdown time is reached.
            var stopwatch = Stopwatch.StartNew();

            while (_processor.NumberOfMessagesInProgress > 0)
            {
                await Task.Delay(ShutdownPollTime);

                _logger.LogInformation(
                    "{NumberOfMessagesInProgress} certificate validations in progress after {TimeElapsed} seconds of graceful shutdown",
                    _processor.NumberOfMessagesInProgress,
                    stopwatch.Elapsed.Seconds);

                if (stopwatch.Elapsed >= MaxShutdownTime)
                {
                    _logger.LogWarning(
                        "Forcefully shutting down even though there are {NumberOfMessagesInProgress} certificate validations in progress",
                        _processor.NumberOfMessagesInProgress);

                    return;
                }
            }
        }
    }
}