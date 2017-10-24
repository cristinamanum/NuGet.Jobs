// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using NuGet.Jobs;
using NuGet.Jobs.Validation.PackageSigning.Messages;
using NuGet.Services.ServiceBus;

namespace Validation.PackageSigning.ValidateCertificate
{
    internal class Job : JobBase
    {
        private ISubscriptionProcessor<CertificateValidationMessage> _processor;

        public override void Init(IDictionary<string, string> jobArgsDictionary)
        {
            // TODO: Service bus
            // TODO: Storage account for certificates
            // TODO: _processor
        }

        public async override Task Run()
        {
            _processor.Start();

            await Task.Delay(TimeSpan.FromDays(1));

            await _processor.StartShutdownAsync();

            // TODO: don't poll forever.
            while (_processor.NumberOfMessagesInProgress > 0)
            {
                await Task.Delay(TimeSpan.FromSeconds(1));
            }
        }
    }
}