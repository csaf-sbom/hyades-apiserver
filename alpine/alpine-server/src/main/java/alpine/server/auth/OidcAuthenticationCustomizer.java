/*
 * This file is part of Alpine.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.server.auth;

import com.nimbusds.openid.connect.sdk.claims.ClaimsSet;

import alpine.model.OidcUser;

public interface OidcAuthenticationCustomizer {

    OidcProfile createProfile(ClaimsSet claimsSet);

    boolean isProfileComplete(OidcProfile profile, boolean teamSyncEnabled);

    OidcProfile mergeProfiles(OidcProfile left, OidcProfile right);

    OidcUser onAuthenticationSuccess(OidcUser user, OidcProfile profile, String idToken, String accessToken);

}
