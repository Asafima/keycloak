<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        ${msg("samlTestLoginFailedTitle")}
    <#elseif section = "form">
    <div id="kc-info-message">
        <p class="instruction">${msg("samlTestLoginFailedInstruction")}</p>
    </div>
    </#if>
</@layout.registrationLayout>
