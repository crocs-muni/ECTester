<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

   <!-- TODO: figure out how to avoid hard-coding the path -->
   <xsl:import href="/usr/share/xml/docbook/stylesheet/docbook-xsl/fo/docbook.xsl"/>

   <xsl:param name="body.font.family" select="'arial'"/>
   <xsl:param name="body.font.size" select="11"/>

   <!-- https://stackoverflow.com/questions/17237093 -->
   <xsl:param name="body.start.indent">0.25in</xsl:param>

   <!--
   <xsl:param name="body.margin.left">0.75in</xsl:param>
   <xsl:param name="body.margin.left">0.75in</xsl:param>
   -->

</xsl:stylesheet>

