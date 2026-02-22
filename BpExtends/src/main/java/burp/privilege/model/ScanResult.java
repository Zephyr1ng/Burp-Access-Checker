package burp.privilege.model;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.time.LocalDateTime;

/**
 * 扫描结果类
 * 存储单个请求的检测结果
 */
public class ScanResult {
    /**
     * 风险等级
     */
    public enum RiskLevel {
        HIGH("高危", "red"),
        MEDIUM("中危", "orange"),
        LOW("低危", "yellow"),
        INFO("信息", "blue"),
        FALSE_POSITIVE("误报", "gray");

        private final String displayName;
        private final String color;

        RiskLevel(String displayName, String color) {
            this.displayName = displayName;
            this.color = color;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getColor() {
            return color;
        }
    }

    // ========== 基本信息 ==========
    /** 漏洞类型 */
    private VulnerabilityType vulnType;

    /** 风险等级 */
    private RiskLevel riskLevel;

    /** 检测时间 */
    private LocalDateTime scanTime;

    /** 是否已确认（用户标记） */
    private boolean confirmed;

    /** 是否为误报 */
    private boolean falsePositive;

    // ========== 请求信息 ==========
    /** 请求URL */
    private String url;

    /** 请求方法 */
    private String method;

    /** 请求路径 */
    private String path;

    /** 原始请求（摘要） */
    private String originalRequest;

    /** 测试请求（摘要） */
    private String testRequest;

    // ========== 响应信息 ==========
    /** 原始响应状态码 */
    private int originalStatusCode;

    /** 测试响应状态码 */
    private int testStatusCode;

    /** 原始响应（摘要，前500字符） */
    private String originalResponse;

    /** 测试响应（摘要，前500字符） */
    private String testResponse;

    /** 响应相似度（0-100） */
    private double similarity;

    // ========== 认证信息 ==========
    /** 原始凭证名称 */
    private String originalCredentialName;

    /** 测试凭证名称 */
    private String testCredentialName;

    // ========== 差异信息 ==========
    /** 响应差异高亮（用于展示） */
    private String diffHighlight;

    /** 备注 */
    private String notes;

    // ========== 完整请求对象（用于发送到Repeater） ==========
    /** 原始请求对象 */
    private HttpRequest originalHttpRequest;

    /** 测试请求对象 */
    private HttpRequest testHttpRequest;

    public ScanResult() {
        this.scanTime = LocalDateTime.now();
        this.riskLevel = RiskLevel.INFO;
    }

    public ScanResult(VulnerabilityType vulnType, String url, String method) {
        this();
        this.vulnType = vulnType;
        this.url = url;
        this.method = method;
    }

    // ========== Getters and Setters ==========

    public VulnerabilityType getVulnType() {
        return vulnType;
    }

    public void setVulnType(VulnerabilityType vulnType) {
        this.vulnType = vulnType;
    }

    public RiskLevel getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(RiskLevel riskLevel) {
        this.riskLevel = riskLevel;
    }

    public LocalDateTime getScanTime() {
        return scanTime;
    }

    public void setScanTime(LocalDateTime scanTime) {
        this.scanTime = scanTime;
    }

    public boolean isConfirmed() {
        return confirmed;
    }

    public void setConfirmed(boolean confirmed) {
        this.confirmed = confirmed;
    }

    public boolean isFalsePositive() {
        return falsePositive;
    }

    public void setFalsePositive(boolean falsePositive) {
        this.falsePositive = falsePositive;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getOriginalRequest() {
        return originalRequest;
    }

    public void setOriginalRequest(String originalRequest) {
        this.originalRequest = originalRequest;
    }

    public String getTestRequest() {
        return testRequest;
    }

    public void setTestRequest(String testRequest) {
        this.testRequest = testRequest;
    }

    public int getOriginalStatusCode() {
        return originalStatusCode;
    }

    public void setOriginalStatusCode(int originalStatusCode) {
        this.originalStatusCode = originalStatusCode;
    }

    public int getTestStatusCode() {
        return testStatusCode;
    }

    public void setTestStatusCode(int testStatusCode) {
        this.testStatusCode = testStatusCode;
    }

    public String getOriginalResponse() {
        return originalResponse;
    }

    public void setOriginalResponse(String originalResponse) {
        this.originalResponse = originalResponse;
    }

    public String getTestResponse() {
        return testResponse;
    }

    public void setTestResponse(String testResponse) {
        this.testResponse = testResponse;
    }

    public double getSimilarity() {
        return similarity;
    }

    public void setSimilarity(double similarity) {
        this.similarity = similarity;
    }

    public String getOriginalCredentialName() {
        return originalCredentialName;
    }

    public void setOriginalCredentialName(String originalCredentialName) {
        this.originalCredentialName = originalCredentialName;
    }

    public String getTestCredentialName() {
        return testCredentialName;
    }

    public void setTestCredentialName(String testCredentialName) {
        this.testCredentialName = testCredentialName;
    }

    public String getDiffHighlight() {
        return diffHighlight;
    }

    public void setDiffHighlight(String diffHighlight) {
        this.diffHighlight = diffHighlight;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public HttpRequest getOriginalHttpRequest() {
        return originalHttpRequest;
    }

    public void setOriginalHttpRequest(HttpRequest originalHttpRequest) {
        this.originalHttpRequest = originalHttpRequest;
    }

    public HttpRequest getTestHttpRequest() {
        return testHttpRequest;
    }

    public void setTestHttpRequest(HttpRequest testHttpRequest) {
        this.testHttpRequest = testHttpRequest;
    }

    /**
     * 获取状态码显示文本
     */
    public String getStatusCodeText() {
        return originalStatusCode + " -> " + testStatusCode;
    }

    /**
     * 获取相似度显示文本
     */
    public String getSimilarityText() {
        return String.format("%.1f%%", similarity);
    }

    /**
     * 获取漏洞类型显示文本
     */
    public String getVulnTypeText() {
        return vulnType != null ? vulnType.getDisplayName() : "未知";
    }

    @Override
    public String toString() {
        return "ScanResult{" +
                "vulnType=" + vulnType +
                ", riskLevel=" + riskLevel +
                ", url='" + url + '\'' +
                ", method='" + method + '\'' +
                ", similarity=" + similarity +
                '}';
    }
}
