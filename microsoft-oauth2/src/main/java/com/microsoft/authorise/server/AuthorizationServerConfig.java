package com.microsoft.authorise.server;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import java.util.Arrays;

/**
 * Copyright 2013-2033 Estee Lauder(zgq65751348@gmail.com).
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.ydm01.com/index.do
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>
 *
 * @Auth Estee Lauder
 * @See  Auth2.0认证服务配置
 * {@code  }.
 * @Date 2021/2/20  14:01
 * </p>
 */
@Configuration
@EnableAuthorizationServer
@AllArgsConstructor
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {


    /** 令牌持久化配置 */
    private final TokenStore tokenStore;
    /** 客户端详情服务 */
    private final ClientDetailsService clientDetailsService;
    /** 认证管理器 */
    private final AuthenticationManager authenticationManager;
    /** 授权码服务 */
    private final AuthorizationCodeServices authorizationCodeServices;
    /** jwtToken解析器 */
    private final JwtAccessTokenConverter jwtAccessTokenConverter;

    private final RedisConnectionFactory redisConnectionFactory;

    @Bean
    public TokenStore redisTokenStore(){
        return new RedisTokenStore(redisConnectionFactory);
    }

    /**
     * 客户端详情服务配置 （demo采用本地内存存储）
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients
                // 使用本地内存存储
                .inMemory()
                // 客户端id
                .withClient("client_1")
                // 客户端密码
                .secret(new BCryptPasswordEncoder().encode("123456"))
                // 该客户端允许授权的类型
                .authorizedGrantTypes("authorization_code", "password", "client_credentials", "implicit", "refresh_token")
                // 该客户端允许授权的范围
                .scopes("all")
                // false跳转到授权页面，true不跳转，直接发令牌
                .autoApprove(false);
    }

    /**
     * 配置访问令牌端点
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
        endpoints
                // 认证管理器
                .authenticationManager(authenticationManager)
                // 授权码服务
                .authorizationCodeServices(authorizationCodeServices)
                // 令牌管理服务    .tokenServices(tokenServices())
                .tokenStore(redisTokenStore())
                .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
    }

    /**
     * 配置令牌端点安全约束
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                // oauth/check_token公开
                .checkTokenAccess("permitAll()")
                // oauth/token_key 公开密钥
                .tokenKeyAccess("permitAll()")
                // 允许表单认证
                .allowFormAuthenticationForClients();
    }

    /**
     * 令牌服务配置
     *
     * @return 令牌服务对象
     */
    public AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices tokenServices = new DefaultTokenServices();
        tokenServices.setTokenStore(tokenStore);
        tokenServices.setSupportRefreshToken(true);
        // 令牌增强
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter));
        tokenServices.setTokenEnhancer(tokenEnhancerChain);
        // 令牌默认有效期2小时
        tokenServices.setAccessTokenValiditySeconds(72000);
        // 刷新令牌默认有效期3天
        tokenServices.setRefreshTokenValiditySeconds(2592000);
        return tokenServices;
    }
}
