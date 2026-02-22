package burp.privilege.model;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 认证凭证类
 * 用于存储用户的认证信息（Cookie、Token等）
 */
public class AuthCredential {
    private String name;  // 凭证名称，如"用户A"、"管理员"

    // Cookie
    private String cookie;

    // Authorization Header
    private String authorizationHeader;

    // 自定义Header（如 X-Token, X-Auth-Token等）
    private Map<String, String> customHeaders = new HashMap<>();

    public AuthCredential() {
    }

    public AuthCredential(String name) {
        this.name = name;
    }

    public AuthCredential(String name, String cookie) {
        this.name = name;
        this.cookie = cookie;
    }

    /**
     * 应用此凭证到请求（替换认证信息）
     *
     * @param request 原始请求
     * @return 修改后的请求
     */
    public HttpRequest applyTo(HttpRequest request) {
        HttpRequest modified = request;

        // 替换Cookie
        if (cookie != null && !cookie.isEmpty()) {
            modified = modified.withUpdatedHeader("Cookie", cookie);
        }

        // 替换Authorization Header
        if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
            modified = modified.withUpdatedHeader("Authorization", authorizationHeader);
        }

        // 替换自定义Header
        for (Map.Entry<String, String> entry : customHeaders.entrySet()) {
            modified = modified.withUpdatedHeader(entry.getKey(), entry.getValue());
        }

        return modified;
    }

    /**
     * 移除请求中的所有认证信息（用于未授权检测）
     *
     * @param request 原始请求
     * @return 移除认证信息后的请求
     */
    public static HttpRequest removeAuth(HttpRequest request) {
        List<String> authHeaders = List.of(
                "Cookie",
                "Authorization",
                "X-Auth-Token",
                "X-CSRF-Token",
                "X-Token",
                "Auth-Token",
                "X-Access-Token",
                "X-Session-Token",
                "Authentication"
        );

        HttpRequest modified = request;
        for (String header : authHeaders) {
            if (modified.hasHeader(header)) {
                modified = modified.withRemovedHeader(header);
            }
        }

        return modified;
    }

    /**
     * 获取请求中现有的认证信息作为凭证
     *
     * @param request HTTP请求
     * @return 提取的认证凭证
     */
    public static AuthCredential extractFrom(HttpRequest request, String name) {
        AuthCredential credential = new AuthCredential(name);

        // 提取Cookie
        String cookie = request.headerValue("Cookie");
        if (cookie != null) {
            credential.setCookie(cookie);
        }

        // 提取Authorization
        String auth = request.headerValue("Authorization");
        if (auth != null) {
            credential.setAuthorizationHeader(auth);
        }

        return credential;
    }

    // Getters and Setters

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCookie() {
        return cookie;
    }

    public void setCookie(String cookie) {
        this.cookie = cookie;
    }

    public String getAuthorizationHeader() {
        return authorizationHeader;
    }

    public void setAuthorizationHeader(String authorizationHeader) {
        this.authorizationHeader = authorizationHeader;
    }

    public Map<String, String> getCustomHeaders() {
        return customHeaders;
    }

    public void setCustomHeaders(Map<String, String> customHeaders) {
        this.customHeaders = customHeaders;
    }

    public void addCustomHeader(String name, String value) {
        this.customHeaders.put(name, value);
    }

    /**
     * 获取凭证摘要（用于显示）
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append(name);

        if (cookie != null && !cookie.isEmpty()) {
            String cookiePreview = cookie.length() > 30 ? cookie.substring(0, 30) + "..." : cookie;
            sb.append(" | Cookie: ").append(cookiePreview);
        }

        if (authorizationHeader != null && !authorizationHeader.isEmpty()) {
            sb.append(" | Auth: ").append(authorizationHeader.substring(0, Math.min(20, authorizationHeader.length())));
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return "AuthCredential{" +
                "name='" + name + '\'' +
                ", cookie='" + (cookie != null ? "***" : "null") + '\'' +
                ", authorizationHeader='" + (authorizationHeader != null ? "***" : "null") + '\'' +
                '}';
    }
}
