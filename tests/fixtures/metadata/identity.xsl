<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  <xsl:output method="xml" encoding="UTF-8" indent="no"/>
  <!-- Identity transform: pass everything through unchanged -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>
