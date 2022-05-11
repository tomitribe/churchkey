/*
 * Copyright 2021 Tomitribe and community
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.churchkey.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class PemTest {

    @Test
    public void test() {

        final String data = "red1 red2 red3 red4 red5 red6 red7 red8 red9 red10 red11 red12 r" +
                "ed13 red14 red15 red16 red17 red18 red19 red20 green1 green2 gre" +
                "en3 green4 green5 green6 green7 green8 green9 green10 green11 gr" +
                "een12 green13 green14 green15 green16 green17 green18 green19 gr" +
                "een20 blue1 blue2 blue3 blue4 blue5 blue6 blue7 blue8 blue9 blue" +
                "10 blue11 blue12 blue13 blue14 blue15 blue16 blue17 blue18 blue1" +
                "9 blue20";

        final String formatted = Pem.builder()
                .data(data)
                .type("color strings")
                .wrap(50)
                .format();

        assertEquals("-----BEGIN COLOR STRINGS-----\n" +
                "cmVkMSByZWQyIHJlZDMgcmVkNCByZWQ1IHJlZDYgcmVkNyByZW\n" +
                "Q4IHJlZDkgcmVkMTAgcmVkMTEgcmVkMTIgcmVkMTMgcmVkMTQg\n" +
                "cmVkMTUgcmVkMTYgcmVkMTcgcmVkMTggcmVkMTkgcmVkMjAgZ3\n" +
                "JlZW4xIGdyZWVuMiBncmVlbjMgZ3JlZW40IGdyZWVuNSBncmVl\n" +
                "bjYgZ3JlZW43IGdyZWVuOCBncmVlbjkgZ3JlZW4xMCBncmVlbj\n" +
                "ExIGdyZWVuMTIgZ3JlZW4xMyBncmVlbjE0IGdyZWVuMTUgZ3Jl\n" +
                "ZW4xNiBncmVlbjE3IGdyZWVuMTggZ3JlZW4xOSBncmVlbjIwIG\n" +
                "JsdWUxIGJsdWUyIGJsdWUzIGJsdWU0IGJsdWU1IGJsdWU2IGJs\n" +
                "dWU3IGJsdWU4IGJsdWU5IGJsdWUxMCBibHVlMTEgYmx1ZTEyIG\n" +
                "JsdWUxMyBibHVlMTQgYmx1ZTE1IGJsdWUxNiBibHVlMTcgYmx1\n" +
                "ZTE4IGJsdWUxOSBibHVlMjA=\n" +
                "-----END COLOR STRINGS-----\n", formatted);

        final Pem parsed = Pem.parse(formatted);
        assertEquals(data, new String(parsed.getData()));
        assertEquals("-----BEGIN COLOR STRINGS-----", parsed.getHeader());
        assertEquals("-----END COLOR STRINGS-----", parsed.getFooter());
        assertEquals("COLOR STRINGS", parsed.getType());
        assertEquals(50, parsed.getWrap());
        assertEquals(0, parsed.getAttributes().size());
    }

    @Test
    public void testSSH2Format() {

        final String data = "red1 red2 red3 red4 red5 red6 red7 red8 red9 red10 red11 red12 r" +
                "ed13 red14 red15 red16 red17 red18 red19 red20 green1 green2 gre" +
                "en3 green4 green5 green6 green7 green8 green9 green10 green11 gr" +
                "een12 green13 green14 green15 green16 green17 green18 green19 gr" +
                "een20 blue1 blue2 blue3 blue4 blue5 blue6 blue7 blue8 blue9 blue" +
                "10 blue11 blue12 blue13 blue14 blue15 blue16 blue17 blue18 blue1" +
                "9 blue20";

        final String formatted = Pem.builder()
                .data(data)
                .header("---- BEGIN COLOR STRINGS ----")
                .footer("---- END COLOR STRINGS ----")
                .attribute("Comment", "this is some pretty fun stuff")
                .attribute("Language", "English")
                .attribute("Tricky", "These \" characters should be ignored \"")
                .attribute("All Whitespace", "    ")
                .wrap(50)
                .format();

        assertEquals("---- BEGIN COLOR STRINGS ----\n" +
                "Comment: \"this is some pretty fun stuff\"\n" +
                "Language: \"English\"\n" +
                "Tricky: \"These \" characters should be ignored \"\"\n" +
                "All Whitespace: \"    \"\n" +
                "cmVkMSByZWQyIHJlZDMgcmVkNCByZWQ1IHJlZDYgcmVkNyByZW\n" +
                "Q4IHJlZDkgcmVkMTAgcmVkMTEgcmVkMTIgcmVkMTMgcmVkMTQg\n" +
                "cmVkMTUgcmVkMTYgcmVkMTcgcmVkMTggcmVkMTkgcmVkMjAgZ3\n" +
                "JlZW4xIGdyZWVuMiBncmVlbjMgZ3JlZW40IGdyZWVuNSBncmVl\n" +
                "bjYgZ3JlZW43IGdyZWVuOCBncmVlbjkgZ3JlZW4xMCBncmVlbj\n" +
                "ExIGdyZWVuMTIgZ3JlZW4xMyBncmVlbjE0IGdyZWVuMTUgZ3Jl\n" +
                "ZW4xNiBncmVlbjE3IGdyZWVuMTggZ3JlZW4xOSBncmVlbjIwIG\n" +
                "JsdWUxIGJsdWUyIGJsdWUzIGJsdWU0IGJsdWU1IGJsdWU2IGJs\n" +
                "dWU3IGJsdWU4IGJsdWU5IGJsdWUxMCBibHVlMTEgYmx1ZTEyIG\n" +
                "JsdWUxMyBibHVlMTQgYmx1ZTE1IGJsdWUxNiBibHVlMTcgYmx1\n" +
                "ZTE4IGJsdWUxOSBibHVlMjA=\n" +
                "---- END COLOR STRINGS ----\n", formatted);

        final Pem parsed = Pem.parse(formatted);
        assertEquals(data, new String(parsed.getData()));
        assertEquals("---- BEGIN COLOR STRINGS ----", parsed.getHeader());
        assertEquals("---- END COLOR STRINGS ----", parsed.getFooter());
        assertEquals("COLOR STRINGS", parsed.getType());
        assertEquals(50, parsed.getWrap());
        assertEquals(4, parsed.getAttributes().size());
        assertEquals("this is some pretty fun stuff", parsed.getAttributes().get("Comment"));
        assertEquals("English", parsed.getAttributes().get("Language"));
        assertEquals("These \" characters should be ignored \"", parsed.getAttributes().get("Tricky"));
        assertEquals("    ", parsed.getAttributes().get("All Whitespace"));
    }

    @Test
    public void whitespaceInAttributes() {

        final String data = "red1 red2 red3 red4 red5 red6 red7 red8 red9 red10 red11 red12 r" +
                "ed13 red14 red15 red16 red17 red18 red19 red20 green1 green2 gre" +
                "en3 green4 green5 green6 green7 green8 green9 green10 green11 gr" +
                "een12 green13 green14 green15 green16 green17 green18 green19 gr" +
                "een20 blue1 blue2 blue3 blue4 blue5 blue6 blue7 blue8 blue9 blue" +
                "10 blue11 blue12 blue13 blue14 blue15 blue16 blue17 blue18 blue1" +
                "9 blue20";

        final String formatted = "---- BEGIN COLOR STRINGS ----\n" +
                        "    Comment: \"this is some pretty fun stuff\"\n" +
                        "Language : \"English\"  \n" +
                        "Tricky  :   \"These \" characters should be ignored \"\"\n" +
                        " All Whitespace : \"    \"\n" +
                        "cmVkMSByZWQyIHJlZDMgcmVkNCByZWQ1IHJlZDYgcmVkNyByZW\n" +
                        "Q4IHJlZDkgcmVkMTAgcmVkMTEgcmVkMTIgcmVkMTMgcmVkMTQg\n" +
                        "cmVkMTUgcmVkMTYgcmVkMTcgcmVkMTggcmVkMTkgcmVkMjAgZ3\n" +
                        "JlZW4xIGdyZWVuMiBncmVlbjMgZ3JlZW40IGdyZWVuNSBncmVl\n" +
                        "bjYgZ3JlZW43IGdyZWVuOCBncmVlbjkgZ3JlZW4xMCBncmVlbj\n" +
                        "ExIGdyZWVuMTIgZ3JlZW4xMyBncmVlbjE0IGdyZWVuMTUgZ3Jl\n" +
                        "ZW4xNiBncmVlbjE3IGdyZWVuMTggZ3JlZW4xOSBncmVlbjIwIG\n" +
                        "JsdWUxIGJsdWUyIGJsdWUzIGJsdWU0IGJsdWU1IGJsdWU2IGJs\n" +
                        "dWU3IGJsdWU4IGJsdWU5IGJsdWUxMCBibHVlMTEgYmx1ZTEyIG\n" +
                        "JsdWUxMyBibHVlMTQgYmx1ZTE1IGJsdWUxNiBibHVlMTcgYmx1\n" +
                        "ZTE4IGJsdWUxOSBibHVlMjA=\n" +
                        "---- END COLOR STRINGS ----\n";


        final Pem parsed = Pem.parse(formatted);
        assertEquals(data, new String(parsed.getData()));
        assertEquals("---- BEGIN COLOR STRINGS ----", parsed.getHeader());
        assertEquals("---- END COLOR STRINGS ----", parsed.getFooter());
        assertEquals("COLOR STRINGS", parsed.getType());
        assertEquals(50, parsed.getWrap());
        assertEquals(4, parsed.getAttributes().size());
        assertEquals("this is some pretty fun stuff", parsed.getAttributes().get("Comment"));
        assertEquals("English", parsed.getAttributes().get("Language"));
        assertEquals("These \" characters should be ignored \"", parsed.getAttributes().get("Tricky"));
        assertEquals("    ", parsed.getAttributes().get("All Whitespace"));
    }
}
