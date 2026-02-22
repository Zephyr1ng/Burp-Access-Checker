package burp.privilege.scanner;

/**
 * 相似度计算器
 * 用于计算两个响应的相似度
 */
public class SimilarityCalculator {

    /**
     * 计算两个文本的相似度（使用编辑距离算法 / Levenshtein Distance）
     *
     * @param text1 文本1
     * @param text2 文本2
     * @return 相似度百分比（0-100）
     */
    public static double calculate(String text1, String text2) {
        if (text1 == null || text2 == null) {
            return 0;
        }

        int maxLen = Math.max(text1.length(), text2.length());
        if (maxLen == 0) {
            return 100;
        }

        int distance = levenshteinDistance(text1, text2);
        return (1.0 - (double) distance / maxLen) * 100;
    }

    /**
     * 计算Levenshtein距离（编辑距离）
     * 表示将一个字符串转换为另一个字符串所需的最少编辑操作次数
     *
     * @param s1 字符串1
     * @param s2 字符串2
     * @return 编辑距离
     */
    private static int levenshteinDistance(String s1, String s2) {
        int len1 = s1.length();
        int len2 = s2.length();

        // 创建动态规划表
        int[][] dp = new int[len1 + 1][len2 + 1];

        // 初始化第一行和第一列
        for (int i = 0; i <= len1; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= len2; j++) {
            dp[0][j] = j;
        }

        // 填充动态规划表
        for (int i = 1; i <= len1; i++) {
            for (int j = 1; j <= len2; j++) {
                // 如果字符相同，代价为0；否则为1
                int cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;

                dp[i][j] = Math.min(
                        Math.min(dp[i - 1][j] + 1,      // 删除
                                dp[i][j - 1] + 1),      // 插入
                        dp[i - 1][j - 1] + cost         // 替换
                );
            }
        }

        return dp[len1][len2];
    }

    /**
     * 计算JSON响应的相似度
     * 对于JSON响应，可以优化计算方式，例如忽略动态字段（时间戳、token等）
     *
     * @param json1 JSON字符串1
     * @param json2 JSON字符串2
     * @return 相似度百分比（0-100）
     */
    public static double calculateJsonSimilarity(String json1, String json2) {
        if (json1 == null || json2 == null) {
            return 0;
        }

        // 简单实现：标准化后计算相似度
        // 后续可以优化为解析JSON并比较结构

        String normalized1 = normalizeJson(json1);
        String normalized2 = normalizeJson(json2);

        return calculate(normalized1, normalized2);
    }

    /**
     * 标准化JSON字符串
     * 移除空格、换行，忽略动态字段
     *
     * @param json JSON字符串
     * @return 标准化后的JSON
     */
    private static String normalizeJson(String json) {
        if (json == null) {
            return "";
        }

        // 移除空格和换行
        String normalized = json.replaceAll("\\s+", "");

        // 移除常见的动态字段（时间戳、token等）
        normalized = normalized.replaceAll("\"timestamp\":\\d+", "\"timestamp\":0");
        normalized = normalized.replaceAll("\"time\":\\d+", "\"time\":0");
        normalized = normalized.replaceAll("\"token\":\"[^\"]*\"", "\"token\":\"\"");
        normalized = normalized.replaceAll("\"csrf_token\":\"[^\"]*\"", "\"csrf_token\":\"\"");

        return normalized;
    }

    /**
     * 判断相似度是否达到阈值
     *
     * @param similarity 相似度
     * @param threshold 阈值
     * @return 是否达到阈值
     */
    public static boolean meetsThreshold(double similarity, int threshold) {
        return similarity >= threshold;
    }
}
