package burp.privilege.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.privilege.model.AuthCredential;
import burp.privilege.model.ScanConfig;
import burp.privilege.model.ScanResult;
import burp.privilege.model.VulnerabilityType;
import burp.privilege.util.HttpUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 扫描引擎
 * 负责执行实际的扫描工作
 */
public class ScanEngine {

    private final MontoyaApi api;
    private final ScanConfig config;
    private final RequestFilter requestFilter;
    private final ResponseAnalyzer responseAnalyzer;

    private final List<ScanResult> results;
    private final List<ScanProgressListener> listeners;

    private volatile boolean isRunning = false;
    private volatile boolean isPaused = false;
    private ExecutorService executorService;

    public ScanEngine(MontoyaApi api, ScanConfig config) {
        this.api = api;
        this.config = config;
        this.requestFilter = new RequestFilter(config);
        this.responseAnalyzer = new ResponseAnalyzer(config);
        this.results = new ArrayList<>();
        this.listeners = new ArrayList<>();
    }

    /**
     * 添加进度监听器
     */
    public void addProgressListener(ScanProgressListener listener) {
        listeners.add(listener);
    }

    /**
     * 清除监听器
     */
    public void clearListeners() {
        listeners.clear();
    }

    /**
     * 开始扫描
     */
    public void startScan() {
        if (isRunning) {
            api.logging().logToError("扫描已在运行中");
            return;
        }

        isRunning = true;
        isPaused = false;

        // 创建线程池
        executorService = Executors.newFixedThreadPool(config.getThreadCount());

        // 在新线程中执行扫描
        new Thread(this::doScan).start();

        api.logging().logToOutput("越权扫描已启动");
    }

    /**
     * 暂停扫描
     */
    public void pauseScan() {
        isPaused = true;
        api.logging().logToOutput("扫描已暂停");
    }

    /**
     * 恢复扫描
     */
    public void resumeScan() {
        isPaused = false;
        api.logging().logToOutput("扫描已恢复");
    }

    /**
     * 停止扫描
     */
    public void stopScan() {
        isRunning = false;
        if (executorService != null) {
            executorService.shutdownNow();
        }
        api.logging().logToOutput("扫描已停止");
    }

    /**
     * 执行扫描
     */
    private void doScan() {
        try {
            // 1. 获取Proxy历史记录
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            api.logging().logToOutput("共获取 " + history.size() + " 条历史记录");

            // 2. 自动提取原始凭证（如果未配置）
            if (config.getOriginalCredential() == null ||
                config.getOriginalCredential().getCookie() == null ||
                config.getOriginalCredential().getCookie().isEmpty()) {
                extractOriginalCredential(history);
            }

            // 3. 筛选需要扫描的请求
            List<HttpRequest> requestsToScan = new ArrayList<>();
            for (ProxyHttpRequestResponse item : history) {
                if (!isRunning) break;

                HttpRequest request = item.request();
                if (requestFilter.shouldScan(request)) {
                    requestsToScan.add(request);
                }
            }

            int totalRequests = requestsToScan.size();
            api.logging().logToOutput("筛选后待扫描请求: " + totalRequests);

            if (totalRequests == 0) {
                notifyScanComplete();
                return;
            }

            // 3. 对每个请求执行检测
            AtomicInteger completedCount = new AtomicInteger(0);

            List<Future<?>> futures = new ArrayList<>();

            for (HttpRequest request : requestsToScan) {
                if (!isRunning) break;

                // 检查暂停状态
                while (isPaused && isRunning) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        break;
                    }
                }

                if (!isRunning) break;

                // 提交扫描任务
                Future<?> future = executorService.submit(() -> {
                    try {
                        scanRequest(request);
                    } catch (Exception e) {
                        api.logging().logToError("扫描请求失败: " + e.getMessage());
                    }

                    int completed = completedCount.incrementAndGet();
                    notifyProgress(completed, totalRequests);
                });

                futures.add(future);
            }

            // 4. 等待所有任务完成
            for (Future<?> future : futures) {
                try {
                    future.get();
                } catch (Exception e) {
                    api.logging().logToError("任务执行失败: " + e.getMessage());
                }
            }

        } finally {
            isRunning = false;
            if (executorService != null) {
                executorService.shutdown();
            }
            notifyScanComplete();
        }
    }

    /**
     * 扫描单个请求
     */
    private void scanRequest(HttpRequest originalRequest) {
        try {
            // 1. 获取原始请求的响应
            HttpRequestResponse originalResponse = api.http().sendRequest(originalRequest);
            HttpResponse originalResp = originalResponse.response();

            // 如果原始请求失败，跳过
            if (originalResp.statusCode() >= 400) {
                return;
            }

            // 2. 执行越权测试（使用其他用户凭证）
            for (AuthCredential testCredential : config.getTestCredentials()) {
                if (!isRunning) break;

                ScanResult result = testPrivilegeEscalation(
                        originalRequest,
                        originalResp,
                        testCredential
                );

                if (result != null) {
                    addResult(result);
                }
            }

            // 3. 执行未授权访问测试
            if (config.isTestUnauthorizedAccess()) {
                ScanResult result = testUnauthorizedAccess(
                        originalRequest,
                        originalResp
                );

                if (result != null) {
                    addResult(result);
                }
            }

        } catch (Exception e) {
            api.logging().logToError("扫描请求异常: " + e.getMessage());
        }
    }

    /**
     * 测试越权访问
     */
    private ScanResult testPrivilegeEscalation(
            HttpRequest originalRequest,
            HttpResponse originalResponse,
            AuthCredential testCredential) {

        try {
            // 1. 应用测试凭证到请求
            HttpRequest modifiedRequest = testCredential.applyTo(originalRequest.copyToTempFile());

            // 2. 发送修改后的请求
            HttpRequestResponse testResponse = api.http().sendRequest(modifiedRequest);
            HttpResponse testResp = testResponse.response();

            // 3. 分析响应
            ResponseAnalyzer.AnalysisResult analysisResult =
                    responseAnalyzer.analyzePrivilegeEscalation(originalResponse, testResp);

            // 4. 根据分析结果创建ScanResult
            if (analysisResult == ResponseAnalyzer.AnalysisResult.VULNERABLE) {
                ScanResult result = new ScanResult(VulnerabilityType.PRIVILEGE_ESCALATION,
                        originalRequest.url(), originalRequest.method());

                result.setOriginalStatusCode(originalResponse.statusCode());
                result.setTestStatusCode(testResp.statusCode());

                double similarity = SimilarityCalculator.calculate(
                        originalResponse.bodyToString(),
                        testResp.bodyToString()
                );
                result.setSimilarity(similarity);

                result.setOriginalCredentialName(
                        config.getOriginalCredential() != null ?
                                config.getOriginalCredential().getName() : "原始用户"
                );
                result.setTestCredentialName(testCredential.getName());

                result.setOriginalResponse(ResponseAnalyzer.getResponseSummary(originalResponse, 500));
                result.setTestResponse(ResponseAnalyzer.getResponseSummary(testResp, 500));

                // 保存完整请求对象（用于发送到Repeater）
                result.setOriginalHttpRequest(originalRequest);
                result.setTestHttpRequest(modifiedRequest);

                // 根据相似度设置风险等级
                if (similarity >= 95) {
                    result.setRiskLevel(ScanResult.RiskLevel.HIGH);
                } else if (similarity >= 85) {
                    result.setRiskLevel(ScanResult.RiskLevel.MEDIUM);
                } else {
                    result.setRiskLevel(ScanResult.RiskLevel.LOW);
                }

                return result;
            }

        } catch (Exception e) {
            api.logging().logToError("越权测试失败: " + e.getMessage());
        }

        return null;
    }

    /**
     * 测试未授权访问
     */
    private ScanResult testUnauthorizedAccess(
            HttpRequest originalRequest,
            HttpResponse originalResponse) {

        try {
            // 1. 移除所有认证信息
            HttpRequest modifiedRequest = AuthCredential.removeAuth(originalRequest.copyToTempFile());

            // 2. 发送修改后的请求
            HttpRequestResponse testResponse = api.http().sendRequest(modifiedRequest);
            HttpResponse testResp = testResponse.response();

            // 3. 分析响应
            ResponseAnalyzer.AnalysisResult analysisResult =
                    responseAnalyzer.analyzeUnauthorizedAccess(originalResponse, testResp);

            // 4. 根据分析结果创建ScanResult
            if (analysisResult == ResponseAnalyzer.AnalysisResult.VULNERABLE) {
                ScanResult result = new ScanResult(VulnerabilityType.UNAUTHORIZED_ACCESS,
                        originalRequest.url(), originalRequest.method());

                result.setOriginalStatusCode(originalResponse.statusCode());
                result.setTestStatusCode(testResp.statusCode());

                double similarity = SimilarityCalculator.calculate(
                        originalResponse.bodyToString(),
                        testResp.bodyToString()
                );
                result.setSimilarity(similarity);

                result.setOriginalCredentialName(
                        config.getOriginalCredential() != null ?
                                config.getOriginalCredential().getName() : "原始用户"
                );
                result.setTestCredentialName("无认证");

                result.setOriginalResponse(ResponseAnalyzer.getResponseSummary(originalResponse, 500));
                result.setTestResponse(ResponseAnalyzer.getResponseSummary(testResp, 500));

                // 保存完整请求对象（用于发送到Repeater）
                result.setOriginalHttpRequest(originalRequest);
                result.setTestHttpRequest(modifiedRequest);

                result.setRiskLevel(ScanResult.RiskLevel.HIGH);

                return result;
            } else if (analysisResult == ResponseAnalyzer.AnalysisResult.SUSPICIOUS) {
                // 可疑结果
                ScanResult result = new ScanResult(VulnerabilityType.UNAUTHORIZED_ACCESS,
                        originalRequest.url(), originalRequest.method());

                result.setOriginalStatusCode(originalResponse.statusCode());
                result.setTestStatusCode(testResp.statusCode());

                double similarity = SimilarityCalculator.calculate(
                        originalResponse.bodyToString(),
                        testResp.bodyToString()
                );
                result.setSimilarity(similarity);

                result.setOriginalResponse(ResponseAnalyzer.getResponseSummary(originalResponse, 500));
                result.setTestResponse(ResponseAnalyzer.getResponseSummary(testResp, 500));

                // 保存完整请求对象（用于发送到Repeater）
                result.setOriginalHttpRequest(originalRequest);
                result.setTestHttpRequest(modifiedRequest);

                result.setRiskLevel(ScanResult.RiskLevel.INFO);

                return result;
            }

        } catch (Exception e) {
            api.logging().logToError("未授权测试失败: " + e.getMessage());
        }

        return null;
    }

    /**
     * 从Proxy历史记录中自动提取原始凭证
     * 从第一个包含Cookie的目标请求中提取认证信息
     */
    private void extractOriginalCredential(List<ProxyHttpRequestResponse> history) {
        for (ProxyHttpRequestResponse item : history) {
            if (!isRunning) break;

            HttpRequest request = item.request();

            // 检查是否是目标域名的请求
            if (!matchesTargetDomain(request)) {
                continue;
            }

            // 检查是否包含Cookie
            String cookie = request.headerValue("Cookie");
            if (cookie != null && !cookie.isEmpty()) {
                AuthCredential originalCredential = new AuthCredential("原始用户", cookie);

                // 同时检查其他认证头
                String auth = request.headerValue("Authorization");
                if (auth != null && !auth.isEmpty()) {
                    originalCredential.setAuthorizationHeader(auth);
                }

                config.setOriginalCredential(originalCredential);
                api.logging().logToOutput("自动提取原始凭证: " +
                    HttpUtils.getCookieSummary(cookie));
                return;
            }
        }

        api.logging().logToOutput("警告: 未能从历史记录中提取到Cookie，请手动配置原始凭证");
    }

    /**
     * 检查请求是否匹配目标域名
     */
    private boolean matchesTargetDomain(HttpRequest request) {
        if (config.getTargetDomains().isEmpty()) {
            return true;
        }

        String host = request.httpService().host();
        for (String domain : config.getTargetDomains()) {
            if (host.equals(domain) || host.endsWith("." + domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 添加扫描结果
     */
    private synchronized void addResult(ScanResult result) {
        results.add(result);
        notifyResultFound(result);
    }

    /**
     * 获取所有扫描结果
     */
    public List<ScanResult> getResults() {
        return new ArrayList<>(results);
    }

    /**
     * 清除扫描结果
     */
    public void clearResults() {
        results.clear();
        requestFilter.clearTestedUrls();
    }

    /**
     * 通知进度更新
     */
    private void notifyProgress(int completed, int total) {
        for (ScanProgressListener listener : listeners) {
            listener.onProgress(completed, total);
        }
    }

    /**
     * 通知发现结果
     */
    private void notifyResultFound(ScanResult result) {
        for (ScanProgressListener listener : listeners) {
            listener.onResultFound(result);
        }
    }

    /**
     * 通知扫描完成
     */
    private void notifyScanComplete() {
        for (ScanProgressListener listener : listeners) {
            listener.onScanComplete();
        }
    }

    /**
     * 是否正在运行
     */
    public boolean isRunning() {
        return isRunning;
    }

    /**
     * 是否暂停
     */
    public boolean isPaused() {
        return isPaused;
    }

    /**
     * 扫描进度监听器接口
     */
    public interface ScanProgressListener {
        /**
         * 进度更新
         * @param completed 已完成数量
         * @param total 总数量
         */
        void onProgress(int completed, int total);

        /**
         * 发现结果
         * @param result 扫描结果
         */
        void onResultFound(ScanResult result);

        /**
         * 扫描完成
         */
        void onScanComplete();
    }
}
