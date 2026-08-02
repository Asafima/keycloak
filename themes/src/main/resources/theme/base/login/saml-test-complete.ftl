<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("samlTestLoginCompleteTitle")}
    <#elseif section = "form">
    <div id="kc-info-message">
        <p class="instruction">${msg("samlTestLoginCompleteInstruction")}</p>
    </div>
    </#if>
</@layout.registrationLayout>
