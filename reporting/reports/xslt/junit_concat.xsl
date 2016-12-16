<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
  <xsl:output method="xml"/>
  <xsl:template match="/">
    <xsl:variable name="combined">
      <xsl:apply-templates select="files"/>
    </xsl:variable>
    <xsl:copy-of select="exsl:node-set($combined)"/>
  </xsl:template>
  <xsl:template match="files">
    <multifile>
      <xsl:apply-templates select="file"/>
    </multifile>
  </xsl:template>
  <xsl:template match="file">
    <xsl:copy-of select="document(@name)"/>
  </xsl:template>
</xsl:stylesheet>
