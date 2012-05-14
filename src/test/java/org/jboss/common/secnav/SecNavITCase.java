/*
 * JBoss, Home of Professional Open Source.
 * Copyright (c) 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.jboss.common.secnav;

import static org.junit.Assert.fail;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.AccessControlException;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Map;

import javax.management.RuntimeErrorException;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.container.ManifestContainer;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.impl.base.exporter.zip.ZipExporterImpl;
import org.junit.Test;

/**
 * @author baranowb
 */
public class SecNavITCase {

    private static final String _KEY_ALIAS = "store";
    private static final String _KEY_STORE_PASSWORD = "secret";
    private static final String _STORE_FILE = "store.jks";

    @Test
    public void testScope_TestClasses() {
        new TestEd().doRead();
        SecNav.doPrivileged(new PrivilegedAction() {

            @Override
            public Object run() {
                new TestEd().doRead();
                return null;
            }
        });
    }

    @Test
    public void testScope_Read() throws Exception {
        try {
            URL url = createFileURL(true, false);
            createFile(url, false);
            // if this is not here, jar seems to be corrupt!
            Thread.currentThread().sleep(1000);
            SecNav.pushContext(url.toURI());
            SecNav.doPrivileged(new PrivilegedAction() {

                @Override
                public Object run() {
                    new TestEd().doRead();
                    return null;
                }
            });
        } finally {
            SecNav.popContext();
        }
    }

    @Test
    public void testScope_Read_Signed() throws Exception {
        try {
            URL url = createFileURL(true, true);
            createFile(url, true);
            // if this is not here, jar seems to be corrupt!
            Thread.currentThread().sleep(1000);
            SecNav.pushContext(url.toURI());
            SecNav.doPrivileged(new PrivilegedAction() {

                @Override
                public Object run() {
                    new TestEd().doRead();
                    return null;
                }
            });
        } finally {
            SecNav.popContext();
        }
    }

    @Test
    public void testScope_Cannot_Read() throws Exception {
        try {

            URL url = createFileURL(false, false);
            createFile(url, false);
            // if this is not here, jar seems to be corrupt!
            Thread.currentThread().sleep(1000);
            SecNav.pushContext(url.toURI());

            SecNav.doPrivileged(new PrivilegedAction() {

                @Override
                public Object run() {
                    new TestEd().doRead();
                    return null;
                }
            });
            fail();
        } catch (AccessControlException ace) {

        } finally {
            SecNav.popContext();
        }
    }

    @Test
    public void testScope_Cannot_Read_Signed() throws Exception {
        try {

            URL url = createFileURL(false, true);
            createFile(url, true);
            // if this is not here, jar seems to be corrupt!
            Thread.currentThread().sleep(1000);
            SecNav.pushContext(url.toURI());

            SecNav.doPrivileged(new PrivilegedAction() {

                @Override
                public Object run() {
                    new TestEd().doRead();
                    return null;
                }
            });
            fail();
        } catch (AccessControlException ace) {

        } finally {
            SecNav.popContext();
        }
    }

    private static URL createFileURL(boolean canRead, boolean signed) throws MalformedURLException {
        URL baseUrl = SecNavITCase.class.getClassLoader().getResource(".");
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("../jars/can");
        if (!canRead) {
            stringBuilder.append("not");
        }

        if (signed) {
            stringBuilder.append("/signed");
        } else {
            stringBuilder.append("/notsigned");
        }
        stringBuilder.append("/test.jar");
        return new URL(baseUrl, stringBuilder.toString());
    }

    private static void createFile(URL url, boolean signed) throws Exception {
        JavaArchive jar = ShrinkWrap.create(JavaArchive.class);
        // actually not required...
        jar.addClass(TestEd.class);

        File file = new File(url.toURI());

        if (file.exists()) {
            file.delete();
        } else {
            file.getParentFile().mkdirs();
        }

        ManifestContainer manifest = jar.addManifest();

        ZipExporterImpl zipExporter = new ZipExporterImpl(jar);
        zipExporter.exportTo(file, true);
        if (!file.exists()) {
            fail();
        }

        if (signed) {
            // execute jarsigner
            StringBuilder command = new StringBuilder();
            // jarsigner -keystore mykeys -storepass abc123 app.jar johndoe
            URL storeURL = SecNavITCase.class.getClassLoader().getResource(_STORE_FILE);
            command.append("jarsigner -keystore ").append(storeURL.toURI().getSchemeSpecificPart());
            command.append(" -storepass " + _KEY_STORE_PASSWORD);
            command.append(" ").append(file.toString());
            command.append(" ").append(_KEY_ALIAS);
            Runtime.getRuntime().exec(command.toString(), null, file.getParentFile());

        }

    }
    //
    // public static void main(String[] args) throws Exception {
    // File file = new File("/home/baranowb/redhat/git/sec-nav/test.jar");
    // JarFile jarFile = new JarFile(file);
    //
    // System.err.println(">>" + jarFile);
    // JarEntry j1 = null,j2 = null;
    //
    // Map<String, Attributes> entries = jarFile.getManifest().getEntries();
    // for (String key : entries.keySet()) {
    // System.err.println("key[ " + key + " ], value[ " + entries.get(key) + " ]");
    // JarEntry ze = jarFile.getJarEntry(key);
    // if(ze== null){
    // continue;
    // }
    // if(j1 == null){
    // j1 = (JarEntry) ze;
    // }
    // if(j2 == null && j1!=null && j1!=ze){
    // j2 = (JarEntry) ze;
    // }
    // InputStream is = jarFile.getInputStream(ze);
    // while(is.available()>0){
    // is.read();
    // }
    //
    // System.err.println("xxx> "+ze.getCodeSigners());
    // }
    // Enumeration<JarEntry> jarEntries = jarFile.entries();
    // while (jarEntries.hasMoreElements()) {
    // JarEntry entry = jarEntries.nextElement();
    // System.err.println("----" + entry + " --> " + entry.getClass() + " --> " + entry.getCertificates() + " --> "
    // + entry.getCodeSigners());
    //
    // }
    //
    // System.err.print("===========> "+Arrays.equals(j1.getCertificates(), j2.getCertificates()));
    // System.err.print("===========> "+Arrays.equals(j1.getCodeSigners(), j2.getCodeSigners()));
    //
    // File file = new File("/home/baranowb/redhat/git/sec-nav/testXXX.jar");
    // JarFile jarFile = new JarFile(file);
    // System.err.println(">>" + jarFile);
    // Map<String, Attributes> entries = jarFile.getManifest().getEntries();
    // for (String key : entries.keySet()) {
    // System.err.println("key[ " + key + " ], value[ " + entries.get(key) + " ]");
    // Attributes attributes = entries.get(key);
    // for (Object attributeKey : attributes.keySet()) {
    // System.err.println(">>>> key[ " + attributeKey + " ], value[ " + attributes.get(attributeKey) + " ]");
    // }
    //
    // }
    // Enumeration<JarEntry> jarEntries = jarFile.entries();
    // while (jarEntries.hasMoreElements()) {
    // JarEntry entry = jarEntries.nextElement();
    // System.err.println("----" + entry + " --> " + entry.getClass() + " --> " + entry.getCertificates() + " --> "
    // + entry.getCodeSigners());
    //
    // }
    //
    // URI u1 = new URI("file:/target/xxx/zero");
    // URI u2 = new URI("file:/target/-");
    //
    // CodeSource cs1 = new CodeSource(u1.toURL(), (CodeSigner[])null);
    // CodeSource cs2 = new CodeSource(u2.toURL(), (CodeSigner[])null);
    // System.err.println(cs2.implies(cs1));
    //
    // System.err.println(">"+u1.getAuthority());
    // System.err.println(">"+u1.getFragment());
    // System.err.println(">"+u1.getHost());
    // System.err.println(">"+u1.getPath());
    // System.err.println(">"+u1.getPort());
    // System.err.println(">"+u1.getQuery());
    // System.err.println(">"+u1.getRawAuthority());
    // System.err.println(">"+u1.getRawFragment());
    // System.err.println(">"+u1.getRawPath());
    // System.err.println(">"+u1.getRawQuery());
    // System.err.println(">"+u1.getRawSchemeSpecificPart());
    // System.err.println(">"+u1.getRawUserInfo());
    // System.err.println(">"+u1.getScheme());
    // System.err.println(">"+u1.getSchemeSpecificPart());
    // System.err.println(">"+u1.getUserInfo());
    // System.err.println(">>>"+u1);
    //
    // File f = new File(u1);
    //
    //
    // }
}
