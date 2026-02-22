package burp.privilege.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 扫描配置类
 * 存储插件的所有配置信息
 */
public class ScanConfig {
    // ========== 目标配置 ==========
    /** 目标域名列表 */
    private List<String> targetDomains = new ArrayList<>();

    /** 是否仅使用Burp Scope中的目标 */
    private boolean useScopeOnly = false;

    /** 路径包含模式（正则表达式） */
    private List<String> pathIncludePatterns = new ArrayList<>();

    /** 路径排除模式（正则表达式） */
    private List<String> pathExcludePatterns = new ArrayList<>();

    // ========== 认证配置 ==========
    /** 原始凭证（用户A - 从历史请求中提取） */
    private AuthCredential originalCredential;

    /** 测试凭证列表（用户B、用户C等 - 用于越权测试） */
    private List<AuthCredential> testCredentials = new ArrayList<>();

    /** 是否进行未授权访问检测 */
    private boolean testUnauthorizedAccess = true;

    /** 要删除的认证头列表 */
    private List<String> authHeadersToRemove = new ArrayList<>(Arrays.asList(
            "Cookie", "Authorization", "X-Auth-Token", "X-CSRF-Token"
    ));

    // ========== 检测配置 ==========
    /** 相似度阈值（0-100） */
    private int similarityThreshold = 80;

    /** 并发线程数 */
    private int threadCount = 5;

    /** 请求超时时间（秒） */
    private int timeout = 10;

    /** 重试次数 */
    private int retryCount = 1;

    // ========== 过滤配置 ==========
    /** 是否排除静态资源 */
    private boolean excludeStaticResources = true;

    /** 静态资源扩展名 */
    private List<String> staticExtensions = Arrays.asList(
            "js", "css", "png", "jpg", "jpeg", "gif", "ico", "woff", "woff2", "ttf", "svg", "mp4", "mp3"
    );

    /** 是否排除已测试的请求 */
    private boolean excludeTested = true;

    /** 包含的HTTP方法（空表示全部） */
    private List<String> includeMethods = new ArrayList<>();

    /** 排除的HTTP方法 */
    private List<String> excludeMethods = Arrays.asList("OPTIONS", "HEAD", "TRACE");

    // ========== 结果判定配置 ==========
    /** 响应中包含以下关键词时判定为非漏洞 */
    private List<String> denyKeywords = Arrays.asList(
            "没有权限", "未授权", "权限不足", "无权访问",
            "unauthorized", "forbidden", "access denied", "permission denied",
            "请先登录", "未登录", "login required", "authentication required"
    );

    /** 重定向包含以下路径时判定为非漏洞 */
    private List<String> loginRedirectPaths = Arrays.asList(
            "/login", "/signin", "/auth/login", "/auth/signin", "/sso/login"
    );

    public ScanConfig() {
        // 默认配置
    }

    public ScanConfig(String domain) {
        this.targetDomains.add(domain);
    }

    // ========== Getters and Setters ==========

    public List<String> getTargetDomains() {
        return targetDomains;
    }

    public void setTargetDomains(List<String> targetDomains) {
        this.targetDomains = targetDomains;
    }

    public void addTargetDomain(String domain) {
        this.targetDomains.add(domain);
    }

    public boolean isUseScopeOnly() {
        return useScopeOnly;
    }

    public void setUseScopeOnly(boolean useScopeOnly) {
        this.useScopeOnly = useScopeOnly;
    }

    public List<String> getPathIncludePatterns() {
        return pathIncludePatterns;
    }

    public void setPathIncludePatterns(List<String> pathIncludePatterns) {
        this.pathIncludePatterns = pathIncludePatterns;
    }

    public List<String> getPathExcludePatterns() {
        return pathExcludePatterns;
    }

    public void setPathExcludePatterns(List<String> pathExcludePatterns) {
        this.pathExcludePatterns = pathExcludePatterns;
    }

    public AuthCredential getOriginalCredential() {
        return originalCredential;
    }

    public void setOriginalCredential(AuthCredential originalCredential) {
        this.originalCredential = originalCredential;
    }

    public List<AuthCredential> getTestCredentials() {
        return testCredentials;
    }

    public void setTestCredentials(List<AuthCredential> testCredentials) {
        this.testCredentials = testCredentials;
    }

    public void addTestCredential(AuthCredential credential) {
        this.testCredentials.add(credential);
    }

    public boolean isTestUnauthorizedAccess() {
        return testUnauthorizedAccess;
    }

    public void setTestUnauthorizedAccess(boolean testUnauthorizedAccess) {
        this.testUnauthorizedAccess = testUnauthorizedAccess;
    }

    public List<String> getAuthHeadersToRemove() {
        return authHeadersToRemove;
    }

    public void setAuthHeadersToRemove(List<String> authHeadersToRemove) {
        this.authHeadersToRemove = authHeadersToRemove;
    }

    public int getSimilarityThreshold() {
        return similarityThreshold;
    }

    public void setSimilarityThreshold(int similarityThreshold) {
        this.similarityThreshold = Math.max(0, Math.min(100, similarityThreshold));
    }

    public int getThreadCount() {
        return threadCount;
    }

    public void setThreadCount(int threadCount) {
        this.threadCount = Math.max(1, Math.min(50, threadCount));
    }

    public int getTimeout() {
        return timeout;
    }

    public void setTimeout(int timeout) {
        this.timeout = Math.max(1, Math.min(300, timeout));
    }

    public int getRetryCount() {
        return retryCount;
    }

    public void setRetryCount(int retryCount) {
        this.retryCount = Math.max(0, Math.min(5, retryCount));
    }

    public boolean isExcludeStaticResources() {
        return excludeStaticResources;
    }

    public void setExcludeStaticResources(boolean excludeStaticResources) {
        this.excludeStaticResources = excludeStaticResources;
    }

    public List<String> getStaticExtensions() {
        return staticExtensions;
    }

    public void setStaticExtensions(List<String> staticExtensions) {
        this.staticExtensions = staticExtensions;
    }

    public boolean isExcludeTested() {
        return excludeTested;
    }

    public void setExcludeTested(boolean excludeTested) {
        this.excludeTested = excludeTested;
    }

    public List<String> getIncludeMethods() {
        return includeMethods;
    }

    public void setIncludeMethods(List<String> includeMethods) {
        this.includeMethods = includeMethods;
    }

    public List<String> getExcludeMethods() {
        return excludeMethods;
    }

    public void setExcludeMethods(List<String> excludeMethods) {
        this.excludeMethods = excludeMethods;
    }

    public List<String> getDenyKeywords() {
        return denyKeywords;
    }

    public void setDenyKeywords(List<String> denyKeywords) {
        this.denyKeywords = denyKeywords;
    }

    public List<String> getLoginRedirectPaths() {
        return loginRedirectPaths;
    }

    public void setLoginRedirectPaths(List<String> loginRedirectPaths) {
        this.loginRedirectPaths = loginRedirectPaths;
    }
}
