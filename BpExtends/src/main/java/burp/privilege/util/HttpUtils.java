package burp.privilege.util;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * HTTP工具类
 */
public class HttpUtils {

    /**
     * 判断是否为静态资源请求
     */
    public static boolean isStaticResource(HttpRequest request) {
        String extension = request.fileExtension().toLowerCase();
        if (extension.isEmpty()) {
            return false;
        }

        String[] staticExtensions = {
                "js", "css", "png", "jpg", "jpeg", "gif", "ico",
                "woff", "woff2", "ttf", "svg", "eot",
                "mp4", "mp3", "wav", "avi", "mov",
                "zip", "rar", "tar", "gz"
        };

        for (String ext : staticExtensions) {
            if (ext.equals(extension)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 获取请求的简要描述
     */
    public static String getRequestSummary(HttpRequest request) {
        return request.method() + " " + request.url();
    }

    /**
     * 截取字符串到指定长度
     */
    public static String truncate(String str, int maxLength) {
        if (str == null) {
            return "";
        }
        if (str.length() <= maxLength) {
            return str;
        }
        return str.substring(0, maxLength) + "...";
    }

    /**
     * 获取Cookie的简要显示
     */
    public static String getCookieSummary(String cookie) {
        if (cookie == null || cookie.isEmpty()) {
            return "无";
        }
        if (cookie.length() <= 30) {
            return cookie;
        }
        return cookie.substring(0, 30) + "...";
    }
}
