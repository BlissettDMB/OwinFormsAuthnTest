﻿// <copyright file="TestPageExtensions.cs" company="Microsoft Open Technologies, Inc.">
// Copyright 2011-2013 Microsoft Open Technologies, Inc. All rights reserved.
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
// </copyright>

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Owin.Diagnostics;

namespace Owin
{
    using AppFunc = Func<IDictionary<string, object>, Task>;

    public static class WelcomePageExtensions
    {
        public static IAppBuilder UseWelcomePage(this IAppBuilder builder, WelcomePageOptions options)
        {
            if (builder == null)
            {
                throw new ArgumentNullException("builder");
            }

            return builder.Use(typeof(WelcomePageMiddleware), options);
        }

        public static IAppBuilder UseWelcomePage(this IAppBuilder builder, string path)
        {
            return UseWelcomePage(builder, new WelcomePageOptions { Path = path });
        }

        public static IAppBuilder UseWelcomePage(this IAppBuilder builder)
        {
            return UseWelcomePage(builder, new WelcomePageOptions());
        }
    }
}
