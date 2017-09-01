﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Stats.AzureCdnLogs.Common.Collect
{
    /// <summary>
    /// An represention of a Stats collector. 
    /// A collector is a type that copies the files from a <see cref="Stats.AzureCdnLogs.Common.Collect.ILogSource"/> to a <see cref="Stats.AzureCdnLogs.Common.Collect.ILogDestination"/>.
    /// The collector can also transform the lines from the source during the processing.
    /// </summary>
    public abstract class Collector
    {
        private static readonly DateTime _unixTimestamp = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
        protected ILogSource _source;
        protected ILogDestination _destination;
        
        public Collector()
        { }

        /// <summary>
        /// .ctor for the Collector
        /// </summary>
        /// <param name="source">The source of the Collector.</param>
        /// <param name="destination">The destination for the collector.</param>
        public Collector(ILogSource source, ILogDestination destination)
        {
            _source = source;
            _destination = destination;
        }

        /// <summary>
        /// Try to process the files from the source.
        /// After processing the file is cleaned. This means it wil be moved either to a archive or a deadletter container.
        /// </summary>
        /// <param name="maxFileCount">Only max this number of files will be processed at once.</param>
        /// <param name="fileNameTransform">A Func to be used to generate the output file name fro the input filename.</param>
        /// <param name="destinationContentType">The <see cref="Stats.AzureCdnLogs.Common.Collect.ContentType"./></param>
        /// <param name="token">A <see cref="System.Threading.CancellationToken"/> to be used for cancelling the operation.</param>
        /// <returns>A collection of exceptions if any.</returns>
        public virtual async Task<AggregateException> TryProcessAsync(int maxFileCount, Func<string,string> fileNameTransform,  ContentType destinationContentType, CancellationToken token)
        {
            ConcurrentBag<Exception> exceptions = new ConcurrentBag<Exception>();
            try
            {
                var files = await _source.GetFilesAsync(maxFileCount, token);
                var parallelResult = Parallel.ForEach(files, (file) =>
                {
                    if(token.IsCancellationRequested)
                    {
                        return;
                    }
                    if (_source.TakeLockAsync(file, token).Result)
                    {
                        using (var inputStream = _source.OpenReadAsync(file, token).Result)
                        {
                            var writeAction = _destination.WriteAsync(inputStream, ProcessLogStream, fileNameTransform(file.Segments.Last()), destinationContentType, token).
                             ContinueWith(t =>
                             {
                                 AddException(exceptions, t.Exception);
                                 return _source.CleanAsync(file, onError: t.IsFaulted, token:token).Result;
                             }).
                              ContinueWith(t =>
                              {
                                  AddException(exceptions, t.Exception);
                                  return _source.ReleaseLockAsync(file, token).Result;
                              }).
                              ContinueWith(t =>
                              {
                                  AddException(exceptions, t.Exception);
                                  return t.Result;
                              }).Result;
                        }
                    }
                });
            }
            catch (Exception e)
            {
                AddException(exceptions, e);
            }
            return exceptions.Count() > 0 ? new AggregateException(exceptions.ToArray()) : null;
        }

        private void AddException(ConcurrentBag<Exception> exceptions, Exception e)
        {
            if(e == null)
            {
                return;
            }
            if (e is AggregateException)
            {
                foreach (Exception innerEx in ((AggregateException)e).InnerExceptions)
                {
                    AddException(exceptions, innerEx);
                }
            }
            else
            {
                exceptions.Add(e);
            }
        }

        /// <summary>
        /// A method to transform each line from the input stream before writing it to the output stream. It is useful for example to modify the schema of each line.
        /// </summary>
        /// <param name="line">A line from the input stream.</param>
        /// <returns>The transformed line.</returns>
        public virtual OutputLogLine TransformRawLogLine(string line)
        {
            // the default implementation will assume that the entries are space separated and in the correct order
            string[] entries = line.Split(' ');

            return new OutputLogLine(entries[0],
                                    entries[1],
                                    entries[2],
                                    entries[3],
                                    entries[4],
                                    entries[5],
                                    entries[6],
                                    entries[7],
                                    entries[8],
                                    entries[9],
                                    entries[10],
                                    entries[11],
                                    entries[12],
                                    entries[13],
                                    entries[14],
                                    entries[15]);
        }

        protected void ProcessLogStream(Stream sourceStream, Stream targetStream)
        {
            using (var sourceStreamReader = new StreamReader(sourceStream))
            {
                using (var targetStreamWriter = new StreamWriter(targetStream))
                {
                    targetStreamWriter.Write(OutputLogLine.Header);
                    var lineNumber = 0;
                    do
                    {
                        var rawLogLine = TransformRawLogLine(sourceStreamReader.ReadLine());
                        if (rawLogLine != null)
                        {
                            lineNumber++;
                            var logLine = GetParsedModifiedLogEntry(lineNumber, rawLogLine.ToString());
                            if (!string.IsNullOrEmpty(logLine))
                            {
                                targetStreamWriter.Write(logLine);
                            }
                        }
                    }
                    while (!sourceStreamReader.EndOfStream);
                }
            }
        }

        private string GetParsedModifiedLogEntry(int lineNumber, string rawLogEntry)
        {
            var parsedEntry = CdnLogEntryParser.ParseLogEntryFromLine(
                lineNumber,
                rawLogEntry,
                null);

            if (parsedEntry == null)
            {
                return null;
            }
 
            const string spaceCharacter = " ";
            const string dashCharacter = "-";
            var stringBuilder = new StringBuilder();

            // timestamp
            stringBuilder.Append(ToUnixTimeStamp(parsedEntry.EdgeServerTimeDelivered) + spaceCharacter);
            // time-taken
            stringBuilder.Append((parsedEntry.EdgeServerTimeTaken.HasValue ? parsedEntry.EdgeServerTimeTaken.Value.ToString() : dashCharacter) + spaceCharacter);

            // REMOVE c-ip
            stringBuilder.Append(dashCharacter + spaceCharacter);

            // filesize
            stringBuilder.Append((parsedEntry.FileSize.HasValue ? parsedEntry.FileSize.Value.ToString() : dashCharacter) + spaceCharacter);
            // s-ip
            stringBuilder.Append((parsedEntry.EdgeServerIpAddress ?? dashCharacter) + spaceCharacter);
            // s-port
            stringBuilder.Append((parsedEntry.EdgeServerPort.HasValue ? parsedEntry.EdgeServerPort.Value.ToString() : dashCharacter) + spaceCharacter);
            // sc-status
            stringBuilder.Append((parsedEntry.CacheStatusCode ?? dashCharacter) + spaceCharacter);
            // sc-bytes
            stringBuilder.Append((parsedEntry.EdgeServerBytesSent.HasValue ? parsedEntry.EdgeServerBytesSent.Value.ToString() : dashCharacter) + spaceCharacter);
            // cs-method
            stringBuilder.Append((parsedEntry.HttpMethod ?? dashCharacter) + spaceCharacter);
            // cs-uri-stem
            stringBuilder.Append((parsedEntry.RequestUrl ?? dashCharacter) + spaceCharacter);

            // -
            stringBuilder.Append(dashCharacter + spaceCharacter);

            // rs-duration
            stringBuilder.Append((parsedEntry.RemoteServerTimeTaken.HasValue ? parsedEntry.RemoteServerTimeTaken.Value.ToString() : dashCharacter) + spaceCharacter);
            // rs-bytes
            stringBuilder.Append((parsedEntry.RemoteServerBytesSent.HasValue ? parsedEntry.RemoteServerBytesSent.Value.ToString() : dashCharacter) + spaceCharacter);
            // c-referrer
            stringBuilder.Append((parsedEntry.Referrer ?? dashCharacter) + spaceCharacter);
            // c-user-agent
            stringBuilder.Append((parsedEntry.UserAgent ?? dashCharacter) + spaceCharacter);
            // customer-id
            stringBuilder.Append((parsedEntry.CustomerId ?? dashCharacter) + spaceCharacter);
            // x-ec_custom-1
            stringBuilder.AppendLine((parsedEntry.CustomField ?? dashCharacter) + spaceCharacter);

            return stringBuilder.ToString();
        }

        protected static string ToUnixTimeStamp(DateTime dateTime)
        {
            var secondsPastEpoch = (dateTime - _unixTimestamp).TotalSeconds;
            return secondsPastEpoch.ToString(CultureInfo.InvariantCulture);
        }
    }
}
