<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",(realm.displayName!''))}
    <#elseif section = "header">
        ${msg("loginTitleHtml",(realm.displayNameHtml!''))}
    <#elseif section = "form">
        <form id="kc-x509-login-info" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="is_certificate_valid" class="${properties.kcLabelClass!}">Is Certificate Valid?: </label>
                </div>

                    <div class="${properties.kcInputWrapperClass!}">
                        <#if isCertificateValid>
                            <input id="is_certificate_valid" class="${properties.kcInputClass!}" name="is_certificate_valid" value="true" type="text" disabled />
                        <#else>
                            <input id="is_certificate_valid" class="${properties.kcInputClass!}" name="is_certificate_valid" value="false" type="text" disabled />
                        </#if>
                    </div>

                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="is_user_valid" class="${properties.kcLabelClass!}">Is User Valid?: </label>
                </div>

                    <div class="${properties.kcInputWrapperClass!}">
                        <#if isUserValid>
                            <input id="is_user_valid" class="${properties.kcInputClass!}" name="is_user_valid" value="true" type="text" disabled />
                        <#else>
                            <input id="is_user_valid" class="${properties.kcInputClass!}" name="is_user_valid" value="false" type="text" disabled />
                        </#if>
                    </div>

                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="is_user_enabled" class="${properties.kcLabelClass!}">Is User Enabled?: </label>
                </div>

                    <div class="${properties.kcInputWrapperClass!}">
                        <#if isUserEnabled>
                            <input id="is_user_enabled" class="${properties.kcInputClass!}" name="is_user_enabled" value="true" type="text" disabled />
                        <#else>
                            <input id="is_user_enabled" class="${properties.kcInputClass!}" name="is_user_enabled" value="false" type="text" disabled />
                        </#if>
                    </div>

                    <#if isUserValid>
                          <div class="${properties.kcLabelWrapperClass!}">
                             <label for="username" class="${properties.kcLabelClass!}"><#if !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>
                          </div>
                          <div class="${properties.kcInputWrapperClass!}">
                            <input id="username" class="${properties.kcInputClass!}" name="username" value="${(login.username!'')?html}" type="text" disabled />
                         </div>
                    </#if>

            </div>

            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                        <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="Continue"/>
                        <#if isUserValid>
                            <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-cancel" type="submit" value="Ignore"/>
                        </#if>
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>