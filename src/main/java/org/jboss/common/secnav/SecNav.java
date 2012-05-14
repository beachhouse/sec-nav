/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
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

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.DomainCombiner;
import java.security.PermissionCollection;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

/**
 * @author baranowb
 *
 */
public class SecNav {

    private static final AccessControlContext CONTEXT_EMPTY = new AccessControlContext(new ProtectionDomain[0]);
    private static final SecNavDomainCombiner DOMAIN_COMBINER = new SecNavDomainCombiner();
    private static final ThreadLocal<LinkedList<ProtectionDomain>> THREAD_DOMAINS = new ThreadLocal<LinkedList<ProtectionDomain>>();
    private static final ThreadLocal<AccessControlContext> THREAD_CONTEXT = new ThreadLocal<AccessControlContext>();

    public static void pushContext(final URI uri) throws IOException {
        // policyfile should handle empty certs when it processes CS
        if (System.getSecurityManager() == null || Policy.getPolicy() == null) {
            return;
        }
        initThreadLocal();

        final SecurityDetails details = new SecurityDetails();
        extractSecurityDetails(uri, details);

        ProtectionDomain protectionDomain = null;
        if (details.codeSigners == null && details.certificates == null) {
            final CodeSource codeSource = new CodeSource(uri.toURL(), (Certificate[]) null);
            final PermissionCollection permissionCollection = Policy.getPolicy().getPermissions(codeSource);
            protectionDomain = new ProtectionDomain(codeSource, permissionCollection);
        } else {
            // TODO: check if signers and certs always come in pair ?
            final CodeSource signersCodeSource = new CodeSource(uri.toURL(), details.codeSigners);
            final PermissionCollection signersPermissionCollection = Policy.getPolicy().getPermissions(signersCodeSource);
            final CodeSource certificatesCodeSource = new CodeSource(uri.toURL(), details.certificates);
            final PermissionCollection certificatesPermissionCollection = Policy.getPolicy().getPermissions(certificatesCodeSource);
            final boolean useSignersOnly = permissionsCount(signersPermissionCollection) >= permissionsCount(certificatesPermissionCollection) ? true : false;
            final PermissionCollection biggestSetOfPermissions = useSignersOnly ? signersPermissionCollection : certificatesPermissionCollection;
            final CodeSource biggestCodeSource = useSignersOnly ? signersCodeSource: certificatesCodeSource;
            protectionDomain = new ProtectionDomain(biggestCodeSource, biggestSetOfPermissions);
        }

        THREAD_DOMAINS.get().addLast(protectionDomain);
        THREAD_CONTEXT.set(null);

    }

    public static void popContext() {
        if (System.getSecurityManager() == null || Policy.getPolicy() == null) {
            return;
        }
        initThreadLocal();
        LinkedList<ProtectionDomain> list = THREAD_DOMAINS.get();
        if (list.isEmpty()) {
            return;
        }
        THREAD_DOMAINS.get().removeLast();
        THREAD_CONTEXT.set(null);
    }

    public static <T> T doPrivileged(PrivilegedAction<T> action) {
        return AccessController.doPrivileged(action, getCurrentContext());
    }

    public static <T> T doPrivileged(PrivilegedExceptionAction<T> action) throws PrivilegedActionException {
        return AccessController.doPrivileged(action, getCurrentContext());
    }

    private static AccessControlContext getCurrentContext() {
        AccessControlContext context = THREAD_CONTEXT.get();
        if (context != null) {
            return context;
        }
        LinkedList<ProtectionDomain> protectionDomains = THREAD_DOMAINS.get();
        if (protectionDomains == null || protectionDomains.isEmpty()) {
            return CONTEXT_EMPTY;
        }
        ProtectionDomain[] protectionDomainsArray = new ProtectionDomain[protectionDomains.size()];
        protectionDomainsArray = protectionDomains.toArray(protectionDomainsArray);
        context = new AccessControlContext(protectionDomainsArray);
        context = new AccessControlContext(context, DOMAIN_COMBINER);
        THREAD_CONTEXT.set(context);
        return context;
    }

    private static void initThreadLocal() {
        if (THREAD_DOMAINS.get() == null) {
            THREAD_DOMAINS.set(new LinkedList<ProtectionDomain>());
        }
    }

    private static int permissionsCount(PermissionCollection permissionCollection) {
        Enumeration enums = permissionCollection.elements();
        int count = 0;
        while (enums.hasMoreElements()) {
            count++;
            enums.nextElement();
        }
        return count;
    }

    /**
     * @param uri
     * @param details
     * @throws IOException
     */
    private static void extractSecurityDetails(final URI uri, final SecurityDetails securityDetails) throws IOException {
        // TODO: check if we can do this not only for files.
        if (uri.getScheme().equals("file")) {
            JarFile jarFile = null;
            try {
                File file = new File(uri);
                jarFile = new JarFile(file, true);
                // NOTE: this is a bit awkward...
                Manifest manifest = jarFile.getManifest();
                if (manifest == null || manifest.getEntries() == null) {
                    return; // ?
                }

                Map<String, Attributes> attributes = manifest.getEntries();
                for (String key : attributes.keySet()) {
                    if (key.endsWith(".class")) {
                        Attributes keyAttributes = attributes.get(key);
                        boolean signed = false;
                        for (Object attributeKey : keyAttributes.keySet()) {
                            if (attributeKey.toString().contains("Digest")) {
                                signed = true;
                                break;
                            }
                        }
                        if (signed) {
                            JarEntry jarEntry = jarFile.getJarEntry(key);
                            InputStream jarEntryInputStream = null;
                            try {
                                jarEntryInputStream = jarFile.getInputStream(jarEntry);
                                byte[] fakeRead = new byte[255];
                                while (jarEntryInputStream.available() > 0) {
                                    jarEntryInputStream.read(fakeRead);
                                }
                            } finally {
                                jarEntryInputStream.close();
                            }
                            // now we can fetch security stuff;
                            securityDetails.codeSigners = jarEntry.getCodeSigners();
                            securityDetails.certificates = jarEntry.getCertificates();
                        }
                    }
                }
            } finally {
                jarFile.close();
            }
        }
    }

    private static class SecurityDetails {
        CodeSigner[] codeSigners;
        Certificate[] certificates;
    }

    private static class SecNavDomainCombiner implements DomainCombiner {

        @Override
        public ProtectionDomain[] combine(ProtectionDomain[] currentDomains, ProtectionDomain[] assignedDomains) {
            return assignedDomains;
        }

    }
}
