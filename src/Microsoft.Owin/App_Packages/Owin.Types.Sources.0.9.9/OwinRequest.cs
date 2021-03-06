// <copyright file="OwinRequest.cs" company="Microsoft Open Technologies, Inc.">
// Copyright 2013 Microsoft Open Technologies, Inc. All rights reserved.
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

using Owin.Types.AppBuilder;
using Owin.Types.Helpers;
using Owin.Types.Opaque;
using Owin.Types.WebSockets;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using AcceptDelegate = System.Action<System.Collections.Generic.IDictionary<string, object>, System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>>;
using AuthenticateCallbackDelegate = System.Action<System.Security.Principal.IIdentity, System.Collections.Generic.IDictionary<string, string>, System.Collections.Generic.IDictionary<string, object>, object>;
using AuthenticateDelegate = System.Func<string[], System.Action<System.Security.Principal.IIdentity, System.Collections.Generic.IDictionary<string, string>, System.Collections.Generic.IDictionary<string, object>, object>, object, System.Threading.Tasks.Task>;
using UpgradeDelegate = System.Action<System.Collections.Generic.IDictionary<string, object>, System.Func<System.Collections.Generic.IDictionary<string, object>, System.Threading.Tasks.Task>>;

namespace Owin.Types
{
#region OwinRequest

    internal partial struct OwinRequest
    {
        public string Host
        {
            get { return OwinHelpers.GetHost(this); }
            set { SetHeader("Host", value); }
        }

        public Uri Uri
        {
            get { return OwinHelpers.GetUri(this); }
        }

        public static OwinRequest Create()
        {
            var environment = new ConcurrentDictionary<string, object>(StringComparer.Ordinal);
            environment[OwinConstants.RequestHeaders] =
                new ConcurrentDictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            environment[OwinConstants.ResponseHeaders] =
                new ConcurrentDictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            return new OwinRequest(environment);
        }
    }
#endregion

#region OwinRequest.Generated

    [System.CodeDom.Compiler.GeneratedCode("App_Packages", "")]
    internal partial struct OwinRequest
    {
        private readonly IDictionary<string, object> _dictionary;

        public OwinRequest(IDictionary<string, object> dictionary)
        {
            _dictionary = dictionary;
        }

        public IDictionary<string, object> Dictionary
        {
            get { return _dictionary; }
        }

#region Value-type equality
        public bool Equals(OwinRequest other)
        {
            return Equals(_dictionary, other._dictionary);
        }

        public override bool Equals(object obj)
        {
            return obj is OwinRequest && Equals((OwinRequest)obj);
        }

        public override int GetHashCode()
        {
            return (_dictionary != null ? _dictionary.GetHashCode() : 0);
        }

        public static bool operator ==(OwinRequest left, OwinRequest right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(OwinRequest left, OwinRequest right)
        {
            return !left.Equals(right);
        }
#endregion

        public T Get<T>(string key)
        {
            object value;
            return _dictionary.TryGetValue(key, out value) ? (T)value : default(T);
        }

        public OwinRequest Set(string key, object value)
        {
            _dictionary[key] = value;
            return this;
        }


        public string GetHeader(string key)
        {
            return Helpers.OwinHelpers.GetHeader(Headers, key);
        }

        public IEnumerable<string> GetHeaderSplit(string key)
        {
            return Helpers.OwinHelpers.GetHeaderSplit(Headers, key);
        }

        public string[] GetHeaderUnmodified(string key)
        {
            return Helpers.OwinHelpers.GetHeaderUnmodified(Headers, key);
        }

        public OwinRequest SetHeader(string key, string value)
        {
            Helpers.OwinHelpers.SetHeader(Headers, key, value);
            return this;
        }

        public OwinRequest SetHeaderJoined(string key, params string[] values)
        {
            Helpers.OwinHelpers.SetHeaderJoined(Headers, key, values);
            return this;
        }

        public OwinRequest SetHeaderJoined(string key, IEnumerable<string> values)
        {
            Helpers.OwinHelpers.SetHeaderJoined(Headers, key, values);
            return this;
        }

        public OwinRequest SetHeaderUnmodified(string key, params string[] values)
        {
            Helpers.OwinHelpers.SetHeaderUnmodified(Headers, key, values);
            return this;
        }

        public OwinRequest SetHeaderUnmodified(string key, IEnumerable<string> values)
        {
            Helpers.OwinHelpers.SetHeaderUnmodified(Headers, key, values);
            return this;
        }

        public OwinRequest AddHeader(string key, string value)
        {
            Helpers.OwinHelpers.AddHeader(Headers, key, value);
            return this;
        }

        public OwinRequest AddHeaderJoined(string key, params string[] values)
        {
            Helpers.OwinHelpers.AddHeaderJoined(Headers, key, values);
            return this;
        }

        public OwinRequest AddHeaderJoined(string key, IEnumerable<string> values)
        {
            Helpers.OwinHelpers.AddHeaderJoined(Headers, key, values);
            return this;
        }

        public OwinRequest AddHeaderUnmodified(string key, params string[] values)
        {
            Helpers.OwinHelpers.AddHeaderUnmodified(Headers, key, values);
            return this;
        }

        public OwinRequest AddHeaderUnmodified(string key, IEnumerable<string> values)
        {
            Helpers.OwinHelpers.AddHeaderUnmodified(Headers, key, values);
            return this;
        }
    }
#endregion

#region OwinRequest.Spec-CommonKeys

    internal partial struct OwinRequest
    {
        public string RemoteIpAddress
        {
            get { return Get<string>(OwinConstants.CommonKeys.RemoteIpAddress); }
            set { Set(OwinConstants.CommonKeys.RemoteIpAddress, value); }
        }

        public string RemotePort
        {
            get { return Get<string>(OwinConstants.CommonKeys.RemotePort); }
            set { Set(OwinConstants.CommonKeys.RemotePort, value); }
        }

        public string LocalIpAddress
        {
            get { return Get<string>(OwinConstants.CommonKeys.LocalIpAddress); }
            set { Set(OwinConstants.CommonKeys.LocalIpAddress, value); }
        }

        public string LocalPort
        {
            get { return Get<string>(OwinConstants.CommonKeys.LocalPort); }
            set { Set(OwinConstants.CommonKeys.LocalPort, value); }
        }

        public bool IsLocal
        {
            get { return Get<bool>(OwinConstants.CommonKeys.IsLocal); }
            set { Set(OwinConstants.CommonKeys.IsLocal, value); }
        }

        public TextWriter TraceOutput
        {
            get { return Get<TextWriter>(OwinConstants.CommonKeys.TraceOutput); }
            set { Set(OwinConstants.CommonKeys.TraceOutput, value); }
        }

        public Action<Action<object>, object> OnSendingHeaders
        {
            get { return Get<Action<Action<object>, object>>(OwinConstants.CommonKeys.OnSendingHeaders); }
            set { Set(OwinConstants.CommonKeys.OnSendingHeaders, value); }
        }

        public Capabilities Capabilities
        {
            get { return new Capabilities(Get<IDictionary<string, object>>(OwinConstants.CommonKeys.Capabilities)); }
            set { Set(OwinConstants.CommonKeys.Capabilities, value.Dictionary); }
        }
    }
#endregion

#region OwinRequest.Spec-Opaque

    internal partial struct OwinRequest
    {
        public bool CanUpgrade
        {
            get { return UpgradeDelegate != null; }
        }

        public UpgradeDelegate UpgradeDelegate
        {
            get { return Get<UpgradeDelegate>(OwinConstants.OpaqueConstants.Upgrade); }
        }

        public void Upgrade(
            OwinOpaqueParameters parameters,
            Func<OwinOpaque, Task> callback)
        {
            var upgrade = UpgradeDelegate;
            if (upgrade == null)
            {
                throw new NotSupportedException(OwinConstants.OpaqueConstants.Upgrade);
            }
            UpgradeDelegate.Invoke(parameters.Dictionary, opaque => callback(new OwinOpaque(opaque)));
        }

        public void Upgrade(
            Func<OwinOpaque, Task> callback)
        {
            Upgrade(OwinOpaqueParameters.Create(), callback);
        }
    }
#endregion

#region OwinRequest.Spec-Owin

    internal partial struct OwinRequest
    {
        public string OwinVersion
        {
            get { return Get<string>(OwinConstants.OwinVersion); }
            set { Set(OwinConstants.OwinVersion, value); }
        }

        public CancellationToken CallCancelled
        {
            get { return Get<CancellationToken>(OwinConstants.CallCancelled); }
            set { Set(OwinConstants.CallCancelled, value); }
        }

        public string Scheme
        {
            get { return Get<string>(OwinConstants.RequestScheme); }
            set { Set(OwinConstants.RequestScheme, value); }
        }

        public string Method
        {
            get { return Get<string>(OwinConstants.RequestMethod); }
            set { Set(OwinConstants.RequestMethod, value); }
        }

        public string PathBase
        {
            get { return Get<string>(OwinConstants.RequestPathBase); }
            set { Set(OwinConstants.RequestPathBase, value); }
        }

        public string Path
        {
            get { return Get<string>(OwinConstants.RequestPath); }
            set { Set(OwinConstants.RequestPath, value); }
        }

        public string QueryString
        {
            get { return Get<string>(OwinConstants.RequestQueryString); }
            set { Set(OwinConstants.RequestQueryString, value); }
        }

        public string Protocol
        {
            get { return Get<string>(OwinConstants.RequestProtocol); }
            set { Set(OwinConstants.RequestProtocol, value); }
        }

        public IDictionary<string, string[]> Headers
        {
            get { return Get<IDictionary<string, string[]>>(OwinConstants.RequestHeaders); }
            set { Set(OwinConstants.RequestHeaders, value); }
        }

        public Stream Body
        {
            get { return Get<Stream>(OwinConstants.RequestBody); }
            set { Set(OwinConstants.RequestBody, value); }
        }
    }
#endregion

#region OwinRequest.Spec-Security

    internal partial struct OwinRequest
    {
        private static readonly AuthenticateCallbackDelegate AuthenticateIdentityExtraPropertiesDelegate = (identity, extra, properties, state) => ((Action<IIdentity, IDictionary<string, string>, IDictionary<string, object>>)state).Invoke(identity, extra, properties);
        private static readonly AuthenticateCallbackDelegate AuthenticateIdentityExtraDelegate = (identity, extra, properties, state) => ((Action<IIdentity, IDictionary<string, string>>)state).Invoke(identity, extra);
        private static readonly AuthenticateCallbackDelegate AuthenticateIdentityDelegate = (identity, extra, properties, state) => ((Action<IIdentity>)state).Invoke(identity);
        private static readonly AuthenticateCallbackDelegate GetAuthenticationTypesPropertiesDelegate = (identity, extra, properties, state) => ((Action<IDictionary<string, object>>)state).Invoke(properties);

        public IPrincipal User
        {
            get { return Get<IPrincipal>(OwinConstants.Security.User); }
            set { Set(OwinConstants.Security.User, value); }
        }

        [SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures",
            Justification = "Following Owin conventions.")]
        public AuthenticateDelegate AuthenticateDelegate
        {
            get { return Get<AuthenticateDelegate>(OwinConstants.Security.Authenticate); }
            set { Set(OwinConstants.Security.Authenticate, value); }
        }

        [SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures",
            Justification = "Following Owin conventions.")]
        public Task GetAuthenticationTypes(Action<IDictionary<string, object>, object> callback, object state)
        {
            return AuthenticateDelegate.Invoke(null, (ignore1, ignore2, extra, innerState) =>
                callback.Invoke(extra, innerState), state);
        }

        [SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures",
            Justification = "Following Owin conventions.")]
        public Task GetAuthenticationTypes(Action<IDictionary<string, object>> callback)
        {
            return AuthenticateDelegate.Invoke(null, GetAuthenticationTypesPropertiesDelegate, callback);
        }

        [SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures",
            Justification = "Following Owin conventions.")]
        public Task Authenticate(string[] authenticationTypes, Action<IIdentity, IDictionary<string, string>,
            IDictionary<string, object>, object> callback, object state)
        {
            return AuthenticateDelegate.Invoke(authenticationTypes, callback, state);
        }

        [SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures",
            Justification = "Following Owin conventions.")]
        public Task Authenticate(string[] authenticationTypes, Action<IIdentity, IDictionary<string, string>,
            IDictionary<string, object>> callback)
        {
            return AuthenticateDelegate.Invoke(authenticationTypes, AuthenticateIdentityExtraPropertiesDelegate, callback);
        }

        [SuppressMessage("Microsoft.Design", "CA1006:DoNotNestGenericTypesInMemberSignatures",
            Justification = "Following Owin conventions.")]
        public Task Authenticate(string[] authenticationTypes, Action<IIdentity,
            IDictionary<string, string>> callback)
        {
            return AuthenticateDelegate.Invoke(authenticationTypes, AuthenticateIdentityExtraDelegate, callback);
        }

        public Task Authenticate(string[] authenticationTypes, Action<IIdentity> callback)
        {
            return AuthenticateDelegate.Invoke(authenticationTypes, AuthenticateIdentityDelegate, callback);
        }
    }
#endregion

#region OwinRequest.Spec-WebSocket

    internal partial struct OwinRequest
    {
        public bool CanAccept
        {
            get { return AcceptDelegate != null; }
        }

        public AcceptDelegate AcceptDelegate
        {
            get { return Get<AcceptDelegate>(OwinConstants.WebSocket.Accept); }
        }

        public void Accept(
            OwinWebSocketParameters parameters,
            Func<OwinWebSocket, Task> callback)
        {
            var accept = AcceptDelegate;
            if (accept == null)
            {
                throw new NotSupportedException(OwinConstants.WebSocket.Accept);
            }
            accept.Invoke(
                parameters.Dictionary,
                webSocket => callback(new OwinWebSocket(webSocket)));
        }

        public void Accept(
            string subProtocol,
            Func<OwinWebSocket, Task> callback)
        {
            Accept(OwinWebSocketParameters.Create(subProtocol), callback);
        }

        public void Accept(
            Func<OwinWebSocket, Task> callback)
        {
            Accept(OwinWebSocketParameters.Create(), callback);
        }
    }
#endregion

}
