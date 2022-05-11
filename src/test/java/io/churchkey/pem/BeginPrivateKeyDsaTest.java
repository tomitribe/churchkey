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
package io.churchkey.pem;

import org.junit.Test;
import io.churchkey.Key;
import io.churchkey.Keys;
import io.churchkey.Resource;
import org.tomitribe.util.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.DSAPrivateKey;

import static org.junit.Assert.assertEquals;

public class BeginPrivateKeyDsaTest {

    @Test
    public void opensslDSAPrivateKey() throws Exception {
        final Resource resources = Resource.resource(this.getClass().getSimpleName());
        final byte[] bytes = resources.bytes("openssl-dsaprivatekey-3072.pem");
        final Key key = Keys.decode(bytes);
        final DSAPrivateKey privateKey = (DSAPrivateKey) key.getKey();

        assertBigInteger("x", privateKey.getX(), "" +
                "7D44BBD37D39F551F52841C332CD68E3E6EE281CEF6CA34B59D9B7CF2CA11800");

        assertBigInteger("p", privateKey.getParams().getP(), "" +
                "8C30CA86F8D1BE736583B28925716BCDFAD596860A678CE1498E8AC8564CD2CC" +
                "E5FC714F3BBC78404668E5CB3A36D1EC70914E20A5F79274225AB32E514CC14A" +
                "3D35B524ED6CA5FB6E5A540F637BDB66EE77C1E57E17678F47BB87471D4C2426" +
                "9BC6CFDB3CA947752F7A9D033F83F0D46521250E9524AAB6A98B6BF667B554B2" +
                "27385CCDEE3EA239ADC886A181FA04BA89CB5C01DBF28F33F76092CB204905F6" +
                "026B6E6AAAC2927AEB40CF5DEC55B9878E5FAC6FA9CF2E48A81B2C83342AFD9F" +
                "C3FD7F3929B7AC5FD4BAA47D6B071014040C5A57AD0F370E2E3B1812A2122493" +
                "FED62052104A1FFD07B8E35510AEE0AAC0E12C9CACA7FD476626CB8B05CB39AD" +
                "70E8F1C05310E56FBEE58638BE75988246F9E827F235C930B2233CB98134751B" +
                "224F4AAA6F28A0FB5B032AE22771470EBB77EC606609A594EE19374726FCE4AA" +
                "7C420CE50AD5068CA8FAA242A5EFC605B9C08E6D509CE4A4E6E0C180BBF5064C" +
                "FD9DB96D78F7A79A97F481C54FB82382B1FB6EF14CB35DB01D33748E537C03F3");

        assertBigInteger("q", privateKey.getParams().getQ(), "" +
                "F7BF79F6D58A8A90F16761755EAC0EB18C722208968004B2DDADA241263A0E99");

        assertBigInteger("g", privateKey.getParams().getG(), "" +
                "5E71E1126FAD52239C493188E5B6A7FFBC861E0FC33B7112983842A05DCFDEEA" +
                "8231F63A9DF7BC100885A55785A38F1196200D9FCC98BF2096034AF3132BDD2F" +
                "AD4FAA907076A4E267AB945392044D3EA13A0338F538C45D60035D97AD525478" +
                "58B5DA4DAEB2245921DC7179038FF2A556A303A06ADF1601780FF7D603E0F60A" +
                "A7EE4BAEDFB1C7D8CF183872F681C4F6FCEEF1D97C06746358B4EEB5C087AE57" +
                "2849BA76DCC15AE12D8FEF769E0583CDF5077B4BFBCA024ADC10A662B8C3B250" +
                "07EF3478E12FE1926A7883E5FEF25C0D2964B5F4D24863E6AC942FBA6BE2810A" +
                "7D41523048ACA39BABCC56F7B3097F94E04914E4C17786893C02D83EB8E90A7A" +
                "204A4C7021AAF5A53B3D48BFD33C1F441B7AB5B4B51450BC861D6B5E26DA73F0" +
                "8E65EC5FE9FA2A72348BAFDCD71C126D353341EE18820335DF2C19D01B9D1737" +
                "DEA95578D503D8C75184B777022CDD8D32328E85C70AEC21ABE71BFB75A5CFDD" +
                "77FC738CEA45C48A44B1A4E67394592AA955B4D8E09D81007BCBB91AD13D68DB");
    }

    @Test
    public void javaDSAPrivateKey() throws Exception {
        final Resource resources = Resource.resource(this.getClass().getSimpleName());
        final byte[] bytes = resources.bytes("java-dsaprivatekey-3072.pem");

        final Key key = Keys.decode(bytes);
        final DSAPrivateKey privateKey = (DSAPrivateKey) key.getKey();

        assertBigInteger("x", privateKey.getX(), "" +
                "4740514706213F462F244288A429E6F6BF9E5752B066C4881ADBEF2F23B06A42");

        assertBigInteger("p", privateKey.getParams().getP(), "" +
                "EA9CDA9F5FBDA66DD830494609405687AB7CF38538E058D1E2F68DEA95364866" +
                "E1C05BEACDED24227EDEE28CAD80BCECAD39913BE3B713267B3B96C8D9F0F6A0" +
                "3B5DFC9222D5CFE4AFCC9982F33784F760C3B759AEBE3BBE9098A6B84C96F1FD" +
                "E44CE11C084C2A082C7A76A0EF142928B4F328406AB9BEB24F84577DD0F46CE8" +
                "6FD8F08488269998BF4742D6425F7A0EC75D8660C5DD6F4E3B3D3BEE81B2C21A" +
                "FE8C9E8B84B87192E2CC20F961D2BCD8133AFCF3675AB80681CB374C78F33E29" +
                "D1011083D89F9C5728B94676FCCB1B57BC60288C15D85AE838AE1941C5A20AE2" +
                "B2049B3583FE30DA455DDB3E6AD9B9955CD9BB5681431622BEB0F92DA533FCAB" +
                "496CEBC447AA1BB5A8039522F2DA98FF416289323A64DF626AB6881870927DCE" +
                "E387F13B5C9D24D6CBA1D82ED375A082506EE87BC7AE30067F4A94E2EE363D99" +
                "2C40F2725B5DB4B3525EBDE22BBBFD0FA124A588B0F5A4ACB3A86951AFF09F8C" +
                "8198FB5B53DA0C931CEDC598B4F835B779D04D99026C7BA08C4B27F118AC1E3D");

        assertBigInteger("q", privateKey.getParams().getQ(), "" +
                "C4EEAC2BBAB79BD831946D717A56A6E687547AA8E9C5494A5A4B2F4CA13D6C11");

        assertBigInteger("g", privateKey.getParams().getG(), "" +
                "42E5FA7844F8FA9D8998D830D004E7B15B1D276BCBE5F12C35EC90C1A25F5832" +
                "018A6724BD9CDBE803B675509BED167F3D7CF8599FC865C6D5A0F79158C1BC91" +
                "8F00A944D0AD0F38F520FB91D85D82674D0D5F874FAA5FCDFE56CD178C1AFDC7" +
                "CE8795727B7DEE966ED0B3C5CEDCEF8ACA628BEFEBF2D105C7AFF8EB0DA9C961" +
                "0737DD64DCE1237B82C1B2BC8608D55FFDA98D7189444E65883315669C05716B" +
                "DE36C78B130AA3DF2E4D609914C7C8DC470F4E300187C775F81E7B1A9C0DCE40" +
                "5D6EAB2CBB9D9C4EF44412BA573DD403C4ED7BC2364772F56A30C48DE78F5003" +
                "F9371C55262D2C8AC2246ADE3B02FDCFCF5CBFDE74FBCBFE6E0E0FDF3160764F" +
                "84D311C179A40AF679A8F47AB13C8F706893245EB11EDCCE451FA2AB98001998" +
                "7F125D8DC96622D419BA0D71F16C6024DCE9D364C3B26D8EC1A3C828F6C9D14B" +
                "1D0333B95DB77BFDBE3C6BCE5337A1A5A7ACE10111219448447197E2A344CC42" +
                "3BE768BB89E27BE6CBD22085614A5A3360BE23B1BFBB6E6E6471363D32C85D31");
    }

    private void assertBigInteger(final String name, final BigInteger actual, final String expected) {
        assertEquals(name, expected, toHex(actual));
    }

    private String toHex(final BigInteger bigInteger) {
        return Hex.toString(bigInteger.toByteArray()).toUpperCase().replaceAll("^00", "");
    }

    @Test
    public void javaDsaPrivateKeyEncode() throws Exception {
        assertEncode("java-dsaprivatekey-3072.pem");
    }

    @Test
    public void opensslDsaPrivateKeyEncode() throws Exception {
        assertEncode("openssl-dsaprivatekey-3072.pem");
    }

    private void assertEncode(final String name) throws IOException {
        final Resource resources = Resource.resource(this.getClass().getSimpleName());
        final byte[] bytes = resources.bytes(name);

        final Key key = Keys.decode(bytes);
        final byte[] encoded = key.encode(Key.Format.PEM);

        /*
         * Assert we get the same bytes back when we encode the key
         */
        assertEquals(new String(bytes), new String(encoded));
    }
}
