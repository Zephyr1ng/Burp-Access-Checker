package burp.privilege.scanner;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.privilege.model.ScanConfig;

import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.regex.Pattern;

/**
 * 请求过滤器
 * 根据配置筛选需要扫描的请求
 */
public class RequestFilter {

    private final ScanConfig config;
    private final Set<String> testedUrls;

    public RequestFilter(ScanConfig config) {
        this.config = config;
        this.testedUrls = new HashSet<>();
    }

    /**
     * 判断请求是否应该被扫描
     *
     * @param request HTTP请求
     * @return true表示应该扫描，false表示跳过
     */
    public boolean shouldScan(HttpRequest request) {
        try {
            // 1. 检查URL是否已测试
            if (config.isExcludeTested()) {
                String urlKey = getUrlKey(request);
                if (testedUrls.contains(urlKey)) {
                    return false;
                }
            }

            // 2. 检查域名
            if (!matchesTargetDomain(request)) {
                return false;
            }

            // 3. 检查HTTP方法
            if (!matchesMethod(request)) {
                return false;
            }

            // 4. 检查静态资源
            if (config.isExcludeStaticResources() && isStaticResource(request)) {
                return false;
            }

            // 5. 检查路径包含模式
            if (!matchesPathIncludePattern(request)) {
                return false;
            }

            // 6. 检查路径排除模式
            if (matchesPathExcludePattern(request)) {
                return false;
            }

            // 7. 记录已测试URL
            if (config.isExcludeTested()) {
                testedUrls.add(getUrlKey(request));
            }

            return true;

        } catch (Exception e) {
            // 解析错误时跳过该请求
            return false;
        }
    }

    /**
     * 检查是否匹配目标域名
     */
    private boolean matchesTargetDomain(HttpRequest request) {
        if (config.getTargetDomains().isEmpty()) {
            return true;  // 未配置域名则全部匹配
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
     * 检查是否匹配HTTP方法
     */
    private boolean matchesMethod(HttpRequest request) {
        String method = request.method();

        // 检查排除方法
        if (config.getExcludeMethods().contains(method)) {
            return false;
        }

        // 检查包含方法（如果配置了）
        if (!config.getIncludeMethods().isEmpty() &&
            !config.getIncludeMethods().contains(method)) {
            return false;
        }

        return true;
    }

    /**
     * 检查是否为静态资源
     */
    private boolean isStaticResource(HttpRequest request) {
        String extension = request.fileExtension().toLowerCase();

        if (extension.isEmpty()) {
            return false;
        }

        return config.getStaticExtensions().contains(extension);
    }

    /**
     * 检查是否匹配路径包含模式
     */
    private boolean matchesPathIncludePattern(HttpRequest request) {
        if (config.getPathIncludePatterns().isEmpty()) {
            return true;  // 无配置则全部匹配
        }

        String path = request.path();

        for (String pattern : config.getPathIncludePatterns()) {
            try {
                if (Pattern.matches(pattern, path)) {
                    return true;
                }
            } catch (Exception e) {
                // 正则表达式无效，忽略
            }
        }

        return false;
    }

    /**
     * 检查是否匹配路径排除模式
     */
    private boolean matchesPathExcludePattern(HttpRequest request) {
        if (config.getPathExcludePatterns().isEmpty()) {
            return false;
        }

        String path = request.path();

        for (String pattern : config.getPathExcludePatterns()) {
            try {
                if (Pattern.matches(pattern, path)) {
                    return true;
                }
            } catch (Exception e) {
                // 正则表达式无效，忽略
            }
        }

        return false;
    }

    /**
     * 获取URL的唯一标识（用于去重）
     */
    private String getUrlKey(HttpRequest request) {
        return request.method() + ":" + request.url();
    }

    /**
     * 清除已测试URL记录
     */
    public void clearTestedUrls() {
        testedUrls.clear();
    }

    /**
     * 获取已测试URL数量
     */
    public int getTestedUrlCount() {
        return testedUrls.size();
    }
}
