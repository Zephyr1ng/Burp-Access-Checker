package burp.privilege.scanner;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.privilege.model.ScanConfig;
import burp.privilege.model.ScanResult;
import burp.privilege.model.VulnerabilityType;

import java.util.List;

/**
 * 响应分析器
 * 用于分析响应并判定是否存在漏洞
 */
public class ResponseAnalyzer {

    private final ScanConfig config;

    public ResponseAnalyzer(ScanConfig config) {
        this.config = config;
    }

    /**
     * 分析越权测试响应
     *
     * @param originalResponse 原始响应
     * @param testResponse     测试响应（使用其他用户凭证）
     * @return 分析结果
     */
    public AnalysisResult analyzePrivilegeEscalation(
            HttpResponse originalResponse,
            HttpResponse testResponse) {

        int originalStatus = originalResponse.statusCode();
        int testStatus = testResponse.statusCode();

        // 1. 状态码检查
        // 如果原始请求失败，则无法进行比较
        if (originalStatus >= 400) {
            return AnalysisResult.ORIGINAL_REQUEST_FAILED;
        }

        // 如果测试请求失败，可能说明有权限控制
        if (testStatus >= 400) {
            return AnalysisResult.NOT_VULNERABLE;
        }

        // 2. 计算相似度
        double similarity = SimilarityCalculator.calculate(
                originalResponse.bodyToString(),
                testResponse.bodyToString()
        );

        if (!SimilarityCalculator.meetsThreshold(similarity, config.getSimilarityThreshold())) {
            return AnalysisResult.NOT_VULNERABLE;
        }

        // 3. 检查响应中是否包含权限错误提示
        String testBody = testResponse.bodyToString().toLowerCase();
        for (String keyword : config.getDenyKeywords()) {
            if (testBody.contains(keyword.toLowerCase())) {
                return AnalysisResult.NOT_VULNERABLE;
            }
        }

        // 4. 检查重定向
        if (testStatus == 302 || testStatus == 301) {
            String location = testResponse.headerValue("Location");
            if (location != null) {
                String lowerLocation = location.toLowerCase();
                for (String path : config.getLoginRedirectPaths()) {
                    if (lowerLocation.contains(path.toLowerCase())) {
                        return AnalysisResult.NOT_VULNERABLE;
                    }
                }
            }
        }

        // 5. 通过所有检查，可能存在越权漏洞
        return AnalysisResult.VULNERABLE;
    }

    /**
     * 分析未授权访问测试响应
     *
     * @param originalResponse 原始响应
     * @param testResponse     测试响应（删除认证信息）
     * @return 分析结果
     */
    public AnalysisResult analyzeUnauthorizedAccess(
            HttpResponse originalResponse,
            HttpResponse testResponse) {

        int originalStatus = originalResponse.statusCode();
        int testStatus = testResponse.statusCode();

        // 1. 状态码检查
        if (originalStatus >= 400) {
            return AnalysisResult.ORIGINAL_REQUEST_FAILED;
        }

        // 2. 检查401/403
        if (testStatus == 401 || testStatus == 403) {
            return AnalysisResult.NOT_VULNERABLE;
        }

        // 3. 检查重定向到登录页
        if (testStatus == 302 || testStatus == 301) {
            String location = testResponse.headerValue("Location");
            if (location != null) {
                String lowerLocation = location.toLowerCase();
                for (String path : config.getLoginRedirectPaths()) {
                    if (lowerLocation.contains(path.toLowerCase())) {
                        return AnalysisResult.NOT_VULNERABLE;
                    }
                }
            }
        }

        // 4. 检查响应体中的登录提示
        String testBody = testResponse.bodyToString().toLowerCase();
        for (String keyword : config.getDenyKeywords()) {
            if (testBody.contains(keyword.toLowerCase())) {
                return AnalysisResult.NOT_VULNERABLE;
            }
        }

        // 5. 检查是否包含登录表单
        if (containsLoginForm(testBody)) {
            return AnalysisResult.NOT_VULNERABLE;
        }

        // 6. 状态码2xx且有业务数据
        if (testStatus >= 200 && testStatus < 300) {
            if (hasBusinessData(testBody)) {
                return AnalysisResult.VULNERABLE;
            }
        }

        // 7. 相似度高且无明确拒绝
        double similarity = SimilarityCalculator.calculate(
                originalResponse.bodyToString(),
                testResponse.bodyToString()
        );

        if (SimilarityCalculator.meetsThreshold(similarity, config.getSimilarityThreshold())) {
            return AnalysisResult.VULNERABLE;
        }

        return AnalysisResult.SUSPICIOUS;
    }

    /**
     * 检查HTML是否包含登录表单
     */
    private boolean containsLoginForm(String html) {
        // 简单检测：包含form和password输入框
        return html.matches("(?si).*<form[^>]*>.*") &&
               html.matches("(?si).*type\\s*=\\s*[\"']?password[\"']?.*");
    }

    /**
     * 检查响应是否包含业务数据
     */
    private boolean hasBusinessData(String body) {
        // 简单判断：包含JSON数据结构
        if (body.matches(".*\\{.*:.*\\}.*")) {
            return true;
        }

        // 包含常见的业务数据标识
        List<String> dataIndicators = List.of(
                "data", "result", "items", "list", "user", "id", "name"
        );

        String lowerBody = body.toLowerCase();
        for (String indicator : dataIndicators) {
            if (lowerBody.contains("\"" + indicator + "\"")) {
                return true;
            }
        }

        return false;
    }

    /**
     * 获取响应摘要（用于显示）
     */
    public static String getResponseSummary(HttpResponse response, int maxLength) {
        if (response == null) {
            return "无响应";
        }

        String body = response.bodyToString();
        if (body.length() <= maxLength) {
            return body;
        }

        return body.substring(0, maxLength) + "...";
    }

    /**
     * 分析结果枚举
     */
    public enum AnalysisResult {
        /** 存在漏洞 */
        VULNERABLE,

        /** 不存在漏洞 */
        NOT_VULNERABLE,

        /** 可疑，需要人工确认 */
        SUSPICIOUS,

        /** 原始请求失败，无法判断 */
        ORIGINAL_REQUEST_FAILED,

        /** 网络错误 */
        NETWORK_ERROR
    }
}
