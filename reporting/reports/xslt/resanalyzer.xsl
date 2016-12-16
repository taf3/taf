<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
    <html>
    <head>
    <link rel="stylesheet" media="screen" type="text/css" href="css/junit.css" />
    <link rel="stylesheet" type="text/css" href="css/jquery-ui.flick.css" />
    <link rel="stylesheet" type="text/css" href="css/jquery.window.css" />
    </head>
    <body>

    <h1>Automated test report</h1>
    <hr />

    <h2>Summary</h2>
    <xsl:variable name="testCount" select="sum(testsuite/@tests)"/>
    <xsl:variable name="totalCount" select="sum(testsuite/@tests)"/>
    <xsl:variable name="failureCount" select="sum(testsuite/@failures)"/>
    <xsl:variable name="failureUnchanged" select="sum(testsuite/@failures_unchanged)" />
    <xsl:variable name="failureChanged" select="sum(testsuite/@failures_changed)" />
    <table class="summaryTable" border="0" cellpadding="5" cellspacing="2" width="95%">
        <tr valign="top">
            <th>Total tests</th>
            <th>Failures</th>
            <th>Unchanged failures</th>
            <th>Changed failures</th>
        </tr>
        <tr valign="top">
            <xsl:attribute name="class">
                <xsl:choose>
                    <xsl:when test="$failureCount &gt; 0">Failure</xsl:when>
                    <!--<xsl:when test="$errorCount &gt; 0">Error</xsl:when>-->
                </xsl:choose>
            </xsl:attribute>
            <td><xsl:value-of select="$totalCount"/></td>
            <td class="sfailure"><xsl:value-of select="$failureCount"/></td>
            <td class="sfailure"><xsl:value-of select="$failureUnchanged" /></td>
            <td class="sfailure"><xsl:value-of select="$failureChanged" /></td>
        </tr>
    </table>
    <br />

    <table class="suiteTable">
    <xsl:for-each select="testsuite/testcase">
        <xsl:if test="@suite != preceding-sibling::testcase[1]/@suite or not(preceding-sibling::testcase[1]/@suite)">
           <th colspan="6"><p class="tsuite"><xsl:value-of select="@suite"/></p></th>
           <tr>
               <th><p class="theader">Name</p></th>
               <th><p class="theader">Date change</p></th>
               <th><p class="theader">Status</p></th>
               <th><p class="theader">Old failure</p></th>
               <th><p class="theader">New failure</p></th>
               <th><p class="theader">Tag</p></th>
           </tr>
        </xsl:if>
        <tr>
            <td>
                <p class="tcase">
                    <xsl:value-of select="@name"/>
                </p>
            </td>
            <td>
                <p class="tcase">
                    <xsl:value-of select="@date"/>
                </p>
            </td>
            <xsl:if test="@status = 'changed'">
            <td>
                <p class="tcase_red_text">
                    <xsl:value-of select="@status"/>
                </p>
            </td>
            </xsl:if>
            <xsl:if test="@status = 'unchanged'">
            <td>
                <p class="tcase_green_text">
                    <xsl:value-of select="@status"/>
                </p>
            </td>
            </xsl:if>

            <td>
                <p class="tcase">
                    <xsl:value-of select="@old_failure"/>
                </p>
            </td>
            <td>
                <p class="tcase">
                    <xsl:value-of select="@new_failure"/>
                </p>
            </td>
            <td>
                <p class="tcase">
                    <xsl:value-of select="@tag"/>
                </p>
            </td>

        </tr>
    </xsl:for-each>
    </table>
    <script type="text/javascript" src="js/jquery.min.js"></script>
    <script type="text/javascript" src="js/jquery-ui.min.js"></script>
    <script type="text/javascript" src="js/jquery.window.min.js"></script>
    <script type="text/javascript" src="js/junit.js"></script>
    </body>
    </html>
</xsl:template>



<!--
            Style templates
-->
    <!--
    <xsl:template match="failure">
        <span style="color:#ff0000">
        <xsl:value-of select="."/></span>
    </xsl:template>
    -->
    <xsl:template match="failure">
        <xsl:call-template name="display-failures"/>
    </xsl:template>

    <xsl:template match="error">
        <xsl:call-template name="display-failures"/>
    </xsl:template>

<!-- Style for the error and failure in the tescase template -->
    <xsl:template name="display-failures">
        <xsl:choose>
            <xsl:when test="not(@message)">N/A</xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="@message"/>
            </xsl:otherwise>
        </xsl:choose>
        <!-- display the stacktrace -->
        <code>
            <br/><br/>
            <xsl:call-template name="br-replace">
                <xsl:with-param name="word" select="."/>
            </xsl:call-template>
        </code>
        <!-- the later is better but might be problematic for non-21" monitors... -->
        <!--pre><xsl:value-of select="."/></pre-->
    </xsl:template>

<!--
    template that will convert a carriage return into a br tag
    @param word the text from which to convert CR to BR tag
-->
    <xsl:template name="br-replace">
        <xsl:param name="word"/>
        <xsl:choose>
            <xsl:when test="contains($word, '&#xa;')">
                <xsl:value-of select="substring-before($word, '&#xa;')"/>
                <br/>
                <xsl:call-template name="br-replace">
                    <xsl:with-param name="word" select="substring-after($word, '&#xa;')"/>
                </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="$word"/>
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>

    <xsl:template name="display-time">
        <xsl:param name="value"/>
        <xsl:value-of select="format-number($value,'0.000')"/>
    </xsl:template>

    <xsl:template name="display-percent">
        <xsl:param name="value"/>
        <xsl:value-of select="format-number($value,'0.00%')"/>
    </xsl:template>


</xsl:stylesheet>
