package burp.privilege;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;
import burp.privilege.ui.MainTab;

/**
 * Burp Suite 越权扫描插件
 *
 * 插件功能：
 * 1. 从Burp Proxy历史记录中筛选指定域名的请求
 * 2. 使用不同用户的Cookie替换原始Cookie进行越权测试
 * 3. 删除认证信息进行未授权访问测试
 * 4. 分析响应相似度和状态码判定是否存在漏洞
 *
 * 使用方法：
 * 1. 在"配置"标签页中配置目标域名和Cookie
 * 2. 点击"开始扫描"按钮开始扫描
 * 3. 在"结果"标签页中查看扫描结果
 *
 * @author Privilege Escalation Scanner
 * @version 1.0.0
 */
public class PrivilegeEscalationExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        // 设置扩展信息
        api.extension().setName("越权扫描器");
        api.logging().logToOutput("=================================================");
        api.logging().logToOutput("  越权扫描器 v1.0.0");
        api.logging().logToOutput("  水平越权 / 垂直越权 / 未授权访问检测");
        api.logging().logToOutput("=================================================");

        try {
            // 创建并注册主Tab
            MainTab mainTab = new MainTab(api);
            api.userInterface().registerSuiteTab("越权扫描", mainTab);

            api.logging().logToOutput("插件加载成功!");
            api.logging().logToOutput("请配置目标域名和Cookie后开始扫描。");

        } catch (Exception e) {
            api.logging().logToError("插件加载失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
