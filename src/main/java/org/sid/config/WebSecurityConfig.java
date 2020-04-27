package org.sid.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Timer;

import javax.annotation.Resource;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.sid.error.CustomHttp403ForbiddenEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLBootstrap;
import org.springframework.security.saml.SAMLEntryPoint;
import org.springframework.security.saml.SAMLLogoutFilter;
import org.springframework.security.saml.SAMLLogoutProcessingFilter;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.CachingMetadataManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataDisplayFilter;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataGeneratorFilter;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.HTTPArtifactBinding;
import org.springframework.security.saml.processor.HTTPPAOS11Binding;
import org.springframework.security.saml.processor.HTTPPostBinding;
import org.springframework.security.saml.processor.HTTPRedirectDeflateBinding;
import org.springframework.security.saml.processor.HTTPSOAP11Binding;
import org.springframework.security.saml.processor.SAMLBinding;
import org.springframework.security.saml.processor.SAMLProcessorImpl;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.ArtifactResolutionProfile;
import org.springframework.security.saml.websso.ArtifactResolutionProfileImpl;
import org.springframework.security.saml.websso.SingleLogoutProfile;
import org.springframework.security.saml.websso.SingleLogoutProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfile;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.saml.websso.WebSSOProfileImpl;
import org.springframework.security.saml.websso.WebSSOProfileOptions;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	/** https://blog.imaginea.com/implementing-java-single-signon-with-saml/ **/
	
	/** configuração para authentication spring security **/
	
	@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
        	.addFilterBefore(this.metadataGeneratorFilter(), ChannelProcessingFilter.class)
        	.addFilterAfter(this.samlFilter(), BasicAuthenticationFilter.class)
        	.addFilterBefore(this.samlFilter(), CsrfFilter.class)
            .authorizeRequests()
                .antMatchers("/", "/403", "/saml/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
            .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/home", true)
                //.defaultSuccessUrl("/saml/login", true)
                .permitAll()
                .and()
            .logout()
                .permitAll()
                .and()
                .exceptionHandling().authenticationEntryPoint(new CustomHttp403ForbiddenEntryPoint());
    }
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/webjars/**", "/saml/**");
		web.ignoring().antMatchers("/css/**","/fonts/**","/libs/**");
	}
	
	@Resource(name = "utilisateurService")
    private UserDetailsService userDetailsService;
	
	@Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(this.userDetailsService).passwordEncoder(encoder());
    }

    @Bean
    public BCryptPasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }
    
    /** fim configuração para authentication spring security **/
    
    /** authentication with SAML **/
    
    @Bean
    public SAMLEntryPoint samlEntryPoint() {
        SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
        samlEntryPoint.setDefaultProfileOptions(this.defaultWebSSOProfileOptions());
        return samlEntryPoint;
    }
    
    @Bean
    public WebSSOProfileOptions defaultWebSSOProfileOptions() {
        WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
        webSSOProfileOptions.setIncludeScoping(false);
        return webSSOProfileOptions;
    }
    
    /** WebSSOProfileConsumer Class is able to process Response objects returned from the IDP after 
     * SP initialized SSO or unsolicited response from IDP. **/
    @Bean
    public WebSSOProfileConsumer webSSOprofileConsumer() {
        return new WebSSOProfileConsumerImpl();
    }
  
    // SAML 2.0 Web SSO profile
    /** WebSSOProfile Class implements WebSSO profile and offers capabilities for SP initialized SSO 
     * and process Response coming from IDP or IDP initialized SSO. 
     * HTTP-POST and HTTP-Redirect bindings are supported. **/
    @Bean
    public WebSSOProfile webSSOprofile() {
        return new WebSSOProfileImpl();
    }
  
    @Bean
    public SingleLogoutProfile logoutprofile() {
        return new SingleLogoutProfileImpl();
    }
    
    @Bean
    public VelocityEngine velocityEngine() {
        return VelocityFactory.getEngine();
    }
  
    @Bean(initMethod = "initialize")
    public StaticBasicParserPool parserPool() {
        return new StaticBasicParserPool();
    }
  
    @Bean(name = "parserPoolHolder")
    public ParserPoolHolder parserPoolHolder() {
        return new ParserPoolHolder();
    }
    
 // Setup advanced info about metadata
    @Bean
    public ExtendedMetadata extendedMetadata() {
	    ExtendedMetadata extendedMetadata = new ExtendedMetadata();
	    extendedMetadata.setIdpDiscoveryEnabled(true);
	    extendedMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	    extendedMetadata.setSignMetadata(true);
	    extendedMetadata.setEcpEnabled(true);
	    return extendedMetadata;
    }
    
    @Bean
    public HttpClient httpClient() {
        return new HttpClient(multiThreadedHttpConnectionManager());
    }
  
    @Bean
    public MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager() {
        return new MultiThreadedHttpConnectionManager();
    }
    
    /** SAMLContextProviderImpl is responsible for parsing HttpRequest/Response 
     * and determining which local entity (IDP/SP) is responsible for its handling. **/
    @Bean
    public SAMLContextProviderImpl contextProvider() {
        return new SAMLContextProviderImpl();
    }
  
    @Bean
    public static SAMLBootstrap SAMLBootstrap() {
        return new SAMLBootstrap();
    }
  
    @Bean
    public SAMLDefaultLogger samlLogger() {
        return new SAMLDefaultLogger();
    }
    
    /** chave gerada através do comando:
     * keytool -genkeypair -alias bm_keyalias -keypass bm_pass -storepass bm_pass -keystore bm-keystore.jks
     * **/
    @Bean
    public KeyManager keyManager() {
        DefaultResourceLoader loader = new DefaultResourceLoader();
        org.springframework.core.io.Resource storeFile = loader.getResource("classpath:/saml/bm-keystore.jks");
        String storePass = "bm_pass";
        Map<String, String> passwords = new HashMap<>();
        passwords.put("bm_keyalias", "bm_pass");
        String defaultKey = "bm_keyalias";
        return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
    }
    
    @Bean
	@Qualifier("idp-ssocircle")
	public ExtendedMetadataDelegate ssoCircleExtendedMetadataProvider() throws MetadataProviderException {
		String idpSSOCircleMetadataURL = "https://idp.ssocircle.com/meta-idp.xml";
		Timer timer = new Timer(true);
		HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(
				timer, this.httpClient(), idpSSOCircleMetadataURL);
		httpMetadataProvider.setParserPool(this.parserPool());
		ExtendedMetadataDelegate extendedMetadataDelegate = 
				new ExtendedMetadataDelegate(httpMetadataProvider, this.extendedMetadata());
		extendedMetadataDelegate.setMetadataTrustCheck(true);
		extendedMetadataDelegate.setMetadataRequireSignature(false);
		timer.purge();
		return extendedMetadataDelegate;
	}
    
    // IDP Metadata configuration - paths to metadata of IDPs in circle of trust
    // is here
    // Do no forget to call iniitalize method on providers
    @Bean
    @Qualifier("metadata")
    public CachingMetadataManager metadata() throws MetadataProviderException {
        List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
        providers.add(this.ssoCircleExtendedMetadataProvider());
        return new CachingMetadataManager(providers);
    }
 
    // Filter automatically generates default SP metadata
    @Bean
    public MetadataGenerator metadataGenerator() {
        MetadataGenerator metadataGenerator = new MetadataGenerator();
        //metadataGenerator.setEntityId("com:vdenotaris:spring:sp");
        metadataGenerator.setEntityId("br.com.mathidios.sp");
        metadataGenerator.setExtendedMetadata(this.extendedMetadata());
        metadataGenerator.setIncludeDiscoveryExtension(false);
        metadataGenerator.setKeyManager(this.keyManager()); 
        return metadataGenerator;
    }
    
    @Bean
    public MetadataGeneratorFilter metadataGeneratorFilter() {
        return new MetadataGeneratorFilter(this.metadataGenerator());
    }
 
    // The filter is waiting for connections on URL suffixed with filterSuffix
    // and presents SP metadata there
    @Bean
    public MetadataDisplayFilter metadataDisplayFilter() {
        return new MetadataDisplayFilter();
    }
    
 // Processor
 	@Bean
 	public SAMLProcessorImpl processor() {
 		Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
 		bindings.add(httpRedirectDeflateBinding());
 		bindings.add(httpPostBinding());
 		bindings.add(artifactBinding(parserPool(), velocityEngine()));
 		bindings.add(httpSOAP11Binding());
 		bindings.add(httpPAOS11Binding());
 		return new SAMLProcessorImpl(bindings);
 	}
 	
 // Bindings
    private ArtifactResolutionProfile artifactResolutionProfile() {
        final ArtifactResolutionProfileImpl artifactResolutionProfile = 
        		new ArtifactResolutionProfileImpl(httpClient());
        artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
        return artifactResolutionProfile;
    }
    
    @Bean
    public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
        return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
    }
 
    @Bean
    public HTTPSOAP11Binding soapBinding() {
        return new HTTPSOAP11Binding(parserPool());
    }
    
    @Bean
    public HTTPPostBinding httpPostBinding() {
    		return new HTTPPostBinding(this.parserPool(), this.velocityEngine());
    }
    
    @Bean
    public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
    		return new HTTPRedirectDeflateBinding(this.parserPool());
    }
    
    @Bean
    public HTTPSOAP11Binding httpSOAP11Binding() {
    	return new HTTPSOAP11Binding(parserPool());
    }
    
    @Bean
    public HTTPPAOS11Binding httpPAOS11Binding() {
    		return new HTTPPAOS11Binding(parserPool());
    }
    
    // Handler deciding where to redirect user after successful login
    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
                new SavedRequestAwareAuthenticationSuccessHandler();
        successRedirectHandler.setDefaultTargetUrl("/home");
        return successRedirectHandler;
    }
    
	// Handler deciding where to redirect user after failed login
    @Bean
    public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
	    	SimpleUrlAuthenticationFailureHandler failureHandler =
	    			new SimpleUrlAuthenticationFailureHandler();
	    	failureHandler.setUseForward(true);
	    	failureHandler.setDefaultFailureUrl("/500");
	    	return failureHandler;
    }
    
    // Processing filter for WebSSO profile messages
    @Bean
    public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
        SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
        samlWebSSOProcessingFilter.setAuthenticationManager(this.authenticationManager());
        samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(this.successRedirectHandler());
        samlWebSSOProcessingFilter.setAuthenticationFailureHandler(this.authenticationFailureHandler());
        return samlWebSSOProcessingFilter;
    }
    
    // Handler for successful logout
    @Bean
    public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
        SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
        successLogoutHandler.setDefaultTargetUrl("/");
        successLogoutHandler.setAlwaysUseDefaultTargetUrl(true);
        return successLogoutHandler;
    }
    
    // Logout handler terminating local session
    @Bean
    public SecurityContextLogoutHandler logoutHandler() {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.setInvalidateHttpSession(true);
        logoutHandler.setClearAuthentication(true);
        return logoutHandler;
    }
    
    // Overrides default logout processing filter with the one processing SAML
    // messages
    @Bean
    public SAMLLogoutFilter samlLogoutFilter() {
        return new SAMLLogoutFilter(this.successLogoutHandler(),
                new LogoutHandler[] { this.logoutHandler() },
                new LogoutHandler[] { this.logoutHandler() });
    }
    
    // Filter processing incoming logout messages
    // First argument determines URL user will be redirected to after successful
    // global logout
    @Bean
    public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
        return new SAMLLogoutProcessingFilter(this.successLogoutHandler(), this.logoutHandler());
    }
    
    /**
	 * Define the security filter chain in order to support SSO Auth by using SAML 2.0
	 * 
	 * @return Filter chain proxy
	 * @throws Exception
	 */
    @Bean
    public FilterChainProxy samlFilter() throws Exception {
        List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
        
        chains.add(new DefaultSecurityFilterChain(
        		new AntPathRequestMatcher("/saml/metadata/**"), this.metadataDisplayFilter()));
        
        chains.add(new DefaultSecurityFilterChain(
        		new AntPathRequestMatcher("/saml/login/**"), this.samlEntryPoint()));
        
        chains.add(new DefaultSecurityFilterChain(
        		new AntPathRequestMatcher("/saml/SSO/**"), this.samlWebSSOProcessingFilter()));
        
        chains.add(new DefaultSecurityFilterChain(
        		new AntPathRequestMatcher("/saml/logout/**"), this.samlLogoutFilter()));
        
        chains.add(new DefaultSecurityFilterChain(
        		new AntPathRequestMatcher("/saml/SingleLogout/**"), this.samlLogoutProcessingFilter()));
        
//        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
//                samlWebSSOHoKProcessingFilter()));
//        chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
//                samlIDPDiscovery()));
        return new FilterChainProxy(chains);
    }
    
    // SAML Authentication Provider responsible for validating of received SAML
    // messages
//    @Bean
//    public SAMLAuthenticationProvider samlAuthenticationProvider() {
//        SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
//        //samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
//        samlAuthenticationProvider.setForcePrincipalAsString(false);
//        return samlAuthenticationProvider;
//    }
    
    /**
     * Sets a custom authentication provider.
     * 
     * @param   auth SecurityBuilder used to create an AuthenticationManager.
     * @throws  Exception 
     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(samlAuthenticationProvider());
//    }
    
    /** end authentication with SAML **/

}
