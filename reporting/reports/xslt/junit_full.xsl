<?xml version="1.0" encoding="ISO-8859-1"?>

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="multifile">
    <html>
    <head>
    <link rel="stylesheet" media="screen" type="text/css" href="css/junit.css" />
    <link rel="stylesheet" type="text/css" href="css/jquery-ui.flick.css" />
    <link rel="stylesheet" type="text/css" href="css/jquery.window.css" />
    </head>
    <body>

    <h1>Automated test report</h1>
    <hr />

    <xsl:if test="testsuite/header">
        <h2>Environment</h2>
        <table class="infoTable">
            <xsl:variable name="unique-list" select="//info_node[not(.=following::info_node)]" />
            <xsl:for-each select="$unique-list">
                <tr>
                    <td class="tdName"><xsl:value-of select="@name"/></td>
                    <td class="tdValue"><xsl:value-of select="."/></td>
                </tr>
            </xsl:for-each>
        </table>
    </xsl:if>

    <h2>Summary</h2>
    <xsl:variable name="testCount" select="sum(testsuite/@tests)"/>
    <xsl:variable name="totalCount" select="sum(testsuite/@tests)"/>
    <xsl:variable name="errorCount" select="sum(testsuite/@errors)"/>
    <xsl:variable name="failureCount" select="sum(testsuite/@failures)"/>
    <xsl:variable name="setupfailureCount" select="sum(testsuite/@setupfailures)"/>
    <xsl:variable name="skippedCount" select="sum(testsuite/@skips)"/>
    <xsl:variable name="timeCount" select="sum(testsuite/@time)"/>
    <xsl:variable name="successRate" select="($testCount - $failureCount - $setupfailureCount - $skippedCount) div ($testCount - $skippedCount)"/>
    <table class="summaryTable" border="0" cellpadding="5" cellspacing="2" width="95%">
        <tr valign="top">
            <th>Total tests</th>
            <th>Failures</th>
            <th>Errors</th>
            <th>Skipped</th>
            <th>Success rate</th>
            <th>Time</th>
        </tr>
        <tr valign="top">
            <xsl:attribute name="class">
                <xsl:choose>
                    <xsl:when test="$failureCount &gt; 0">Failure</xsl:when>
                    <xsl:when test="$errorCount &gt; 0">Error</xsl:when>
                </xsl:choose>
            </xsl:attribute>
            <td><xsl:value-of select="$totalCount"/></td>
            <td class="sfailure"><xsl:value-of select="$failureCount"/></td>
            <td class="sfailure"><xsl:value-of select="$errorCount"/></td>
            <td class="sskipped"><xsl:value-of select="$skippedCount"/></td>
            <td>
                <xsl:call-template name="display-percent">
                    <xsl:with-param name="value" select="$successRate"/>
                </xsl:call-template>
            </td>
            <td>
                <xsl:call-template name="display-time">
                    <xsl:with-param name="value" select="$timeCount"/>
                </xsl:call-template>
            </td>
        </tr>
    </table>
    <br />

    <table class="suiteTable">
    <xsl:for-each select="testsuite/testcase">
        <xsl:if test="@classname != preceding-sibling::testcase[1]/@classname or not(preceding-sibling::testcase[1]/@classname)">
           <th colspan="6"><p class="tsuite"><xsl:value-of select="@classname"/></p></th>
           <tr>
               <th><p class="theader">TestId</p></th>
               <th><p class="theader">TestCase Name</p></th>
               <th><p class="theader">Status</p></th>
               <th><p class="theader">Defect(s)</p></th>
               <th><p class="theader">Time</p></th>
           </tr>
        </xsl:if>
        <tr>
            <td class="tdCaseId">
                <p class="tcase">
                    <xsl:choose>
                        <xsl:when test="@testid">
                            <a href="http://127.0.0.1:8080/labmanagement/labmanagementserver_web.jsp#isExternalIntegration=true&amp;editable=true&amp;integrationName=testCaseIntegration&amp;testCaseId={@testid}" target="_blank"><xsl:value-of select="@testid"/></a>
                        </xsl:when>
                        <xsl:otherwise>
                            N/A
                        </xsl:otherwise>
                    </xsl:choose>
                </p>
            </td>
            <td>
                <p class="tcase">
                    <xsl:choose>
                        <xsl:when test="@link">
                            <a href="{@link}" target="_blank"><xsl:value-of select="@name"/></a>
                        </xsl:when>
                        <xsl:otherwise>
                            <xsl:value-of select="@name"/>
                        </xsl:otherwise>
                    </xsl:choose>
                </p>
            </td>
            <xsl:choose>
                <xsl:when test="failure">
                    <td class="tdStatus">
                        <div class="testIssue">
                            <div class="issueTitle">
                                <p class="failure">Failure</p>
                            </div>
                            <div class="issueEntry">
                                <pre>
                                    <xsl:apply-templates select="failure"/>
                                </pre>
                            </div>
                        </div>
                    </td>
                </xsl:when>
                <xsl:when test="error">
                    <td class="tdStatus">
                        <div class="testIssue">
                            <div class="issueTitle">
                                <p class="error">Error</p>
                            </div>
                            <div class="issueEntry">
                                <pre>
                                    <xsl:apply-templates select="error"/>
                                </pre>
                            </div>
                        </div>
                    </td>
                </xsl:when>
                <xsl:when test="skipped">
                    <td class="tdStatus"><p class="skipped" title="{skipped/@message}">Skipped</p></td>
                </xsl:when>
                <xsl:otherwise>
                    <xsl:choose>
                        <xsl:when test="@retval">
                            <td class="tdStatus"><p class="success"><xsl:value-of select="@retval"/></p></td>
                        </xsl:when>
                        <xsl:otherwise>
                            <td class="tdStatus"><p class="success">Success</p></td>
                        </xsl:otherwise>
                    </xsl:choose>
                </xsl:otherwise>
            </xsl:choose>
            <td class="tdDefectId">
                <p class="tcase">
                    <xsl:for-each select="defect">
                        <a href="http://127.0.0.1:8080/browse/{@d_id}" target="_blank"><xsl:value-of select="@d_id"/></a><br/>
                    </xsl:for-each>
                </p>
            </td>
            <td class="tdCaseTime">
                <p class="tcase">
                    <xsl:call-template name="display-time">
                        <xsl:with-param name="value" select="@time"/>
                    </xsl:call-template>
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
