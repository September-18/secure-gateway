package com.secure_gateway.config;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouterValidator {

	public static final List<String> openApiEndpoints = List.of("/auth/v1/login", "/auth/v1/forgotpassword",
			"/auth/v1/refresh-token", "/auth/v1/generate-mobile-token",
			"common/v1/preAnnouncement", "common/v1/getApplyUrl",
			"common/v1/publickey", "common/v1/getSecretKeyRSA", "common/v1/fpx/getFpxId", "common/v1/eproc/getEprocId",
			"common/v1/consent/getConsentId", "common/v1/rtp/getRtpId", "/rcas/", "/v3/api-docs/", "/utility/",
			"/dropdown/", "/v3/", "/swagger-ui/", "/error/", "/actuator/", "/rsa/",
			"common/v1/secret-questions/retrieve", "common/v1/secret-questions/retrieveAll",
			"common/v1/secret-questions/validate", "common/v1/secret-questions/initialize",
			"common/v1/int/secret-questions/setup", "common/v1/int/secret-questions/retrieve",
			"common/v1/int/secret-questions/retrieveAll", "common/v1/int/secret-questions/validate",
			"common/v1/int/secret-questions/getAll", "common/v1/int/secret-questions/initialize", "portal/v1/sso-user",
			"/common/v1/publickey");
	public static final List<String> downtimeWhitelistEndpoints = List.of("common/v1/preAnnouncement",
			"common/v1/getApplyUrl", "common/v1/publickey", "common/v1/getSecretKeyRSA", "common/v1/fpx/getFpxId",
			"common/v1/eproc/getEprocId", "common/v1/consent/getConsentId", "common/v1/rtp/getRtpId",
			"/auth/v1/refresh-token", "/auth/v1/generate-mobile-token", "/v3/api-docs/", "/v3/", "/swagger-ui/",
			"common/v1/int/secret-questions/setup", "common/v1/int/secret-questions/retrieve",
			"common/v1/int/secret-questions/retrieveAll", "common/v1/int/secret-questions/validate",
			"common/v1/int/secret-questions/getAll", "common/v1/int/secret-questions/initialize",
			"prelogin/announcements", "prelogin/recommended");
    private static final List<String> tempEndpoints = List.of("/auth/v1/loginWithQuestion");
		private static final List<String> pre2faEndpoints = List.of("/v1/secret-questions/retrieve",
				"/v1/change-password", "/v1/generatePush", "/common/v1/secret-questions/validate",
				"/v1/pushStatus", "/v1/validateSecure2uCode", "/v1/valHardtokenSerialNo", "/v1/valHardtokenOtp", "/v1/session-timeout/log",
				"/v1/registration-incomplete/log", "/v1/refresh-token", "/v1/rsa-analyze");

    public Predicate<String> isSecured =
            request -> openApiEndpoints
                    .stream()
                    .noneMatch(uri -> request.contains(uri));

    public Predicate<String> isBypassDowntime =
            request -> downtimeWhitelistEndpoints
                    .stream()
                    .noneMatch(uri -> request.contains(uri));

    public Predicate<String> isTemporary =
            request -> tempEndpoints
                    .stream()
                    .anyMatch(uri -> request.contains(uri));

	public Predicate<String> is2FA =
			request -> pre2faEndpoints.stream().anyMatch(request::endsWith);
}