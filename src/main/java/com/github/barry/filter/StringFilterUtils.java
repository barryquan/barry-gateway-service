package com.github.barry.filter;

import org.apache.commons.text.StringEscapeUtils;

import com.google.common.base.Strings;

/***
 * <b>字符串过滤工具类
 * 
 * @author barry
 *
 */
public class StringFilterUtils {

    /**
     * <br>
     * <b>直接使用StringEscapeUtils.escapeHtml4()的话，<br>
     * <br>
     * <b>会把Json字符串的双引号也过滤掉，导致Json后续处理解析失败<br>
     * 
     * @param value body Json字符串
     * @return
     */
    public static String escapeHtml5Body(String body) {
        return escapeHtml5(body).replaceAll("&amp;", "&").replaceAll("&quot;", "\"");
    }

    /**
     * <b>对XSS进行编码
     * 
     * @param value 对字符串进行XSS过滤，防止XSS攻击
     * @return
     */
    public static String escapeHtml5(String value) {
        return Strings.isNullOrEmpty(value) ? value : StringEscapeUtils.escapeHtml4(value.trim());
    }
}
