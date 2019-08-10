package com.github.barry.xss;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.commons.text.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.io.buffer.NettyDataBufferFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.base.Strings;

import io.netty.buffer.ByteBufAllocator;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/***
 * 网关统一过滤XSS
 * 
 * @author barry
 * @since 2019年8月1日
 */
@Component
public class XssFilter implements GlobalFilter, Ordered {

    private Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * <b>排序，数值越小越先执行
     */
    @Override
    public int getOrder() {
        return 10;
    }

    /**
     * <b>进行XSS攻击过滤<br>
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest serverHttpRequest = exchange.getRequest();
        String method = serverHttpRequest.getMethodValue();
        String contentType = serverHttpRequest.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
        URI uri = serverHttpRequest.getURI();
        log.debug("请求上来的链接={}", uri.getPath());
        if ("GET".equals(method)) {
            return requestQueryFilter(uri, exchange, chain);
        } else if ((MediaType.APPLICATION_FORM_URLENCODED_VALUE.equalsIgnoreCase(contentType)
                || MediaType.APPLICATION_JSON_VALUE.equalsIgnoreCase(contentType))) {
            return requestBodyFilter(exchange, chain);
        }
        return chain.filter(exchange);
    }

    /**
     * GET 的查询参数过滤XSS、SQL攻击
     * 
     * @param uri
     * @param exchange
     * @param chain
     * @return
     */
    private Mono<Void> requestQueryFilter(URI uri, ServerWebExchange exchange, GatewayFilterChain chain) {
        StringBuilder query = new StringBuilder();
        String originalQuery = uri.getQuery();
        log.debug("获取到的GET请求的参数为={}", originalQuery);
        if (!Strings.isNullOrEmpty(originalQuery)) {
            query.append(escapeHtml5(originalQuery).replaceAll("&amp;", "&"));
            log.debug("编码后，未转码的参数为={}", query.toString());
            log.debug("获取的查询参数RAW={}", uri.getRawQuery());
        }
        String queryTemp;
        try {
            queryTemp = URLEncoder.encode(query.toString(), StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException e) {
            log.error("GET请求参数在转换成URL编码时出错，原因={}", e);
            queryTemp = uri.getRawQuery();
        }
        log.debug("编码后的查找字符串为={}", queryTemp);
        // 对URL参数的&=进行编码还原
        queryTemp = queryTemp.replaceAll("%26", "&").replaceAll("%3D", "=");
        URI newUri = UriComponentsBuilder.fromUri(uri).replaceQuery(queryTemp).build(true).toUri();
        ServerHttpRequest request = exchange.getRequest().mutate().uri(newUri).build();
        return chain.filter(exchange.mutate().request(request).build());
    }

    /***
     * POST、PUT请求的参数修改，防止XSS攻击
     * 
     * @param exchange
     * @param chain
     * @return
     */
    private Mono<Void> requestBodyFilter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequestDecorator serverHttpRequestDecorator = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                Flux<DataBuffer> body = super.getBody();
                return body.map(dataBuffer -> {
                    byte[] content = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(content);
                    // 释放掉内存
                    DataBufferUtils.release(dataBuffer);
                    // 这个就是request body的json格式数据
                    String bodyJson = new String(content, StandardCharsets.UTF_8);
                    log.debug("修改前请求的参数为={}", bodyJson);

                    bodyJson = escapeHtml5Body(bodyJson);
                    log.debug("经过XSS编码后的请求体参数为={}", bodyJson);
                    // 转成字节
                    byte[] bytes = bodyJson.getBytes();
                    return new NettyDataBufferFactory(ByteBufAllocator.DEFAULT).allocateBuffer(bytes.length)
                            .write(bytes);
                });
            }

            // 复写getHeaders方法，删除content-length
            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.putAll(super.getHeaders());
                // 由于修改了请求体的body，导致content-length长度不确定，因此使用分块编码
                httpHeaders.remove(HttpHeaders.CONTENT_LENGTH);
                httpHeaders.set(HttpHeaders.TRANSFER_ENCODING, "chunked");
                return httpHeaders;
            }
        };
        return chain.filter(exchange.mutate().request(serverHttpRequestDecorator).build());
    }

    /**
     * <br>
     * 对XSS进行编码
     * 
     * @param value 对GET请求参数进行XSS编码
     * @return
     */
    private static String escapeHtml5(String value) {
        return Strings.isNullOrEmpty(value) ? value : StringEscapeUtils.escapeHtml4(value.trim());
    }

    /**
     * <br>
     * 对POST、PUT的请求参数进行XSS编码 直接使用StringEscapeUtils.escapeHtml4()的话，<br>
     * <br>
     * 会把Json字符串的双引号也过滤掉，导致Json后续处理解析失败<br>
     * 
     * @param value body Json字符串
     * @return
     */
    private static String escapeHtml5Body(String value) {
        // JSON数据的话，将引号进行还原
        return escapeHtml5(value).replaceAll("&quot;", "\"");
    }

}