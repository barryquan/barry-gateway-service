package com.github.barry.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.support.BodyInserterContext;
import org.springframework.cloud.gateway.support.CachedBodyOutputMessage;
import org.springframework.cloud.gateway.support.DefaultClientResponse;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ReactiveHttpOutputMessage;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.BodyInserter;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.server.ServerWebExchange;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * <b>请求响应数据网关处理<br>
 * <b>如果不需要使用，把{@link Component}注释掉即可<br>
 * <b>如果需要添加自定义过滤的需求，可以重写{@link StringFilterUtils.escapeHtml5Body}<br>
 * <b>如果需要添加自定义返回参数给调用者，请参考方法{@link ResponseFilter.addCustomBodyParam}，实现自定义的需求。
 * 
 * @since 2019年9月19日
 * @author qsr
 *
 */
@Component
public class ResponseFilter implements GlobalFilter, Ordered {

    private Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * <b>响应参数中的响应数据json键
     */
    private static final String BODY_DATA_PARAM = "data";

    /**
     * <b>响应参数中的响应数据data节点下分页数据的键
     */
//    private static final String BODY_PAGE_PARAM = "page";

    /**
     * <b>响应参数中的响应数据data节点下_embedded数据的键
     */
//    private static final String BODY_EMBEDDED_PARAM = "_embedded";

    /**
     * <b>响应参数中的响应数据data节点下的_embedded的节点下resources数据的键
     */
//    private static final String BODY_RESOURCES_PARAM = "resources";

    /**
     * <b>响应头中是否为返回json类型的数据
     */
    private static final String HEADERS_CONTENT_TYPE = "json";

    /**
     * <b>响应体参数中的响应码参数
     */
    private static final String BODY_CODE_PARAM = "code";

    /**
     * <b>响应体参数中的响应码的默认值，默认值为200
     */
    private static final int BODY_CODE_VALUE = 200;

    /**
     * <b> 作为转换json和转成java类的转换工厂，采用构造函数，spring会自动注入
     */
    private ObjectMapper objectMapper;

    /**
     * <b> 是否封装成携带响应码和响应参数的形式，默认为否，即原装输出，不做任何改动<br>
     * <b> 如果为true，则封装成带响应码格式的响应参数，如{code=200,msg="操作成功",data=xxx}<br>
     * <b> 其中xxx为原始的数据<br>
     */
    @Value("${use.format.response:false}")
    private boolean isUseResponseFormat;

    public ResponseFilter(ObjectMapper objectMapper) {
        super();
        this.objectMapper = objectMapper;
    }

    /**
     * <b>排序，数值越小越先执行
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    /**
     * <b>对响应参数进行XSS过滤和添加自定义的响应参数<br>
     */
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        return responseBodyFilter(exchange, chain);
    }

    /***
     * <b>过滤响应的返回值，将拥有XSS攻击的代码进行过滤，并添加自定义状态码的转换
     * 
     * @param exchange
     * @param chain
     * @return
     */
    private Mono<Void> responseBodyFilter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpResponse originalResponse = exchange.getResponse();

        ServerHttpResponseDecorator responseDecorator = new ServerHttpResponseDecorator(exchange.getResponse()) {
            @Override
            public Mono<Void> writeWith(@NonNull Publisher<? extends DataBuffer> body) {
                String originalResponseContentType = exchange
                        .getAttribute(ServerWebExchangeUtils.ORIGINAL_RESPONSE_CONTENT_TYPE_ATTR);

                // 返回的响应头的类型不是json数据的，不做处理。
                if (!Strings.isNullOrEmpty(originalResponseContentType)
                        && !originalResponseContentType.contains(HEADERS_CONTENT_TYPE)) {
                    return super.writeWith(body);
                }
                HttpHeaders httpHeaders = new HttpHeaders();
                httpHeaders.add(HttpHeaders.CONTENT_TYPE, originalResponseContentType);
                ResponseAdapter responseAdapter = new ResponseAdapter(body, httpHeaders);
                DefaultClientResponse clientResponse = new DefaultClientResponse(responseAdapter,
                        ExchangeStrategies.withDefaults());
                Mono<String> modifiedBody = clientResponse.bodyToMono(String.class).flatMap(originalBody -> {
                    log.info("请求返回的body为={}", originalBody);
                    if (Objects.nonNull(originalResponse.getStatusCode())) {
                        if (originalResponse.getStatusCode().is2xxSuccessful()) {

                            // 第一步：进行XSS过滤
                            originalBody = StringFilterUtils.escapeHtml5Body(originalBody);

                            // 第二步：添加自定义参数
                            originalBody = addCustomBodyParam(originalBody);
                        }

                    }
                    return Mono.just(originalBody);
                });

                // 修改后，对响应的body进行封装。
                BodyInserter<Mono<String>, ReactiveHttpOutputMessage> bodyInserter = BodyInserters
                        .fromPublisher(modifiedBody, String.class);
                CachedBodyOutputMessage outputMessage = new CachedBodyOutputMessage(exchange,
                        exchange.getResponse().getHeaders());
                return bodyInserter.insert(outputMessage, new BodyInserterContext()).then(Mono.defer(() -> {
                    Flux<DataBuffer> messageBody = outputMessage.getBody();
                    HttpHeaders headers = getDelegate().getHeaders();
                    if (!headers.containsKey(HttpHeaders.TRANSFER_ENCODING)) {
                        messageBody = messageBody.doOnNext(data -> headers.setContentLength(data.readableByteCount()));
                    }
                    return getDelegate().writeWith(messageBody);
                }));
            }

            @Override
            public Mono<Void> writeAndFlushWith(@NonNull Publisher<? extends Publisher<? extends DataBuffer>> body) {
                return writeWith(Flux.from(body).flatMapSequential(p -> p));
            }
        };
        return chain.filter(exchange.mutate().response(responseDecorator).build());
    }

    /**
     * <b>在响应参数中，添加自定义的参数返回<br>
     * <b>如果是分页搜索的情况，并且搜索不到数据时，添加一个空的搜索集合数据<br>
     * <b>如果是要构造标准的输出，即响应的形式为={code=xxx,data=xxx}的形式<br>
     * <b>首先isUseResponseFormat=true，并且响应参数中不包含code=xxx才会触发。
     * 
     * @param originalBody 经过XSS编码后的响应JSON字符串
     * @return 修改成功返回修改后json字符串，修改失败返回原json字符串
     */
    @SuppressWarnings("unchecked")
    protected String addCustomBodyParam(String originalBody) {

        Map<String, Object> bodyMap = null;
        try {
            bodyMap = objectMapper.readValue(originalBody, Map.class);
        } catch (IOException e) {
            log.error("将响应的JSON字符串转换成Map集合失败，json字符串为={}，失败的原因为={}", originalBody, e);
        }

        // 是否使用标准输出,即使用{code=200,data=xxx}的形式
        if (isUseResponseFormat && !bodyMap.containsKey(BODY_CODE_PARAM)) {
            bodyMap = doResponseFormat(bodyMap);
        }

        try {
            originalBody = objectMapper.writeValueAsString(bodyMap);
        } catch (JsonProcessingException e) {
            log.error("将map类型转换成json失败，返回原字符串，原因={}", e);
        }
        return originalBody;
    }

    /**
     * <b>组装成标准的输出参数进行输出<br>
     * <b> 即使用{code=200,data=xxx}的形式
     * 
     * @param bodyMap
     * @return
     */
    private Map<String, Object> doResponseFormat(Map<String, Object> bodyMap) {
        Map<String, Object> responseMap = new HashMap<>();
        responseMap.put(BODY_CODE_PARAM, BODY_CODE_VALUE);
        responseMap.put(BODY_DATA_PARAM, bodyMap);
        return responseMap;
    }

}