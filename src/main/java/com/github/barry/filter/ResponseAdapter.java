package com.github.barry.filter;

import org.reactivestreams.Publisher;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.client.reactive.ClientHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.util.MultiValueMap;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class ResponseAdapter implements ClientHttpResponse {

    private final Flux<DataBuffer> flux;

    private final HttpHeaders headers;

    @SuppressWarnings({ "unchecked", "rawtypes" })
    public ResponseAdapter(Publisher<? extends DataBuffer> body, HttpHeaders headers) {
        super();
        this.headers = headers;
        if (body instanceof Flux) {
            flux = (Flux<DataBuffer>) body;
        } else {
            flux = ((Mono) body).flux();
        }
    }

    @Override
    public @NonNull Flux<DataBuffer> getBody() {
        return flux;
    }

    @Override
    public @NonNull HttpHeaders getHeaders() {
        return headers;
    }

    @Override
    public HttpStatus getStatusCode() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public int getRawStatusCode() {
        return 0;
    }

    @Override
    public MultiValueMap<String, ResponseCookie> getCookies() {
        return null;
    }

}
