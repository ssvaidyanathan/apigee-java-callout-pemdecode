// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.apigee.edgecallouts;


import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.edgecallouts.util.Debug;
import com.google.apigee.edgecallouts.util.VarResolver;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import com.nimbusds.jose.util.X509CertUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.util.encoders.Hex;

public class PEMDecode implements Execution {
  public static final String CALLOUT_VAR_PREFIX = "PEMDecode";
  public static final String PEM_STRING_PROP = "pem-string";

  private final Map properties;
  private ByteArrayOutputStream stdoutOS;
  private ByteArrayOutputStream stderrOS;
  private PrintStream stdout;
  private PrintStream stderr;

  public PEMDecode(Map properties) throws UnsupportedEncodingException {
    this.properties = properties;
    this.stdoutOS = new ByteArrayOutputStream();
    this.stderrOS = new ByteArrayOutputStream();
    this.stdout = new PrintStream(stdoutOS, true, StandardCharsets.UTF_8.name());
    this.stderr = new PrintStream(stderrOS, true, StandardCharsets.UTF_8.name());
  }

  private void saveOutputs(MessageContext msgCtx) {
    msgCtx.setVariable(CALLOUT_VAR_PREFIX + ".info.stdout", new String(stdoutOS.toByteArray(), StandardCharsets.UTF_8));
    msgCtx.setVariable(CALLOUT_VAR_PREFIX + ".info.stderr", new String(stderrOS.toByteArray(), StandardCharsets.UTF_8));
  }

  public ExecutionResult execute(MessageContext messageContext, ExecutionContext executionContext) {
    try {
      VarResolver vars = new VarResolver(messageContext, properties);
      Debug dbg = new Debug(messageContext, CALLOUT_VAR_PREFIX);

      Boolean debug = vars.getProp("debug", Boolean.class, false);

      String pemString = vars.getRequiredProp(PEM_STRING_PROP,"");

      if (debug) {
        dbg.setVar(PEM_STRING_PROP, pemString);
      }

      Map<String, String> result = decodePEM(pemString);

      for (Map.Entry<String, String> entry : result.entrySet()) {
        messageContext.setVariable(CALLOUT_VAR_PREFIX + "_" + entry.getKey(), entry.getValue());
      }

      return ExecutionResult.SUCCESS;
    } catch (Error | Exception e) {
      e.printStackTrace(stderr);
      return ExecutionResult.ABORT;
    } finally {
      saveOutputs(messageContext);
    }
  }


  public static void main(String args[]) throws IOException, CertificateEncodingException, NoSuchAlgorithmException {
    String pem = new String(Files.readAllBytes(Paths.get("/Users/miguelmendoza/Downloads/example_zso/device_user.pem")));
	Map<String, String> parts = decodePEM(pem);
    for (Map.Entry<String, String> part: parts.entrySet()) {
      System.out.println(part.getKey() + ": " + part.getValue());
    }
  }

  public static Map<String, String> decodePEM(String content) throws IOException, NoSuchAlgorithmException, CertificateEncodingException {
	String contentStr=content.replace("\\n", "\n");
    Map<String, String> parts = new TreeMap<>();
    X509Certificate cert = X509CertUtils.parse(contentStr);

    parts.put("issuerDN", cert.getIssuerDN().toString());
    parts.put("subjectDN", cert.getSubjectDN().toString());
    parts.put("serialNumber", cert.getSerialNumber().toString(16));
    parts.put("notAfter", String.valueOf(cert.getNotAfter().getTime()));
    parts.put("notBefore", String.valueOf(cert.getNotBefore().getTime()));
    parts.put("version", String.valueOf(cert.getVersion()));
    parts.put("criticalExtensionOIDKeys", getOIDKeyList(cert.getCriticalExtensionOIDs()));
    parts.put("nonCriticalExtensionOIDKeys", getOIDKeyList(cert.getNonCriticalExtensionOIDs()));

    Set<String> coids = cert.getCriticalExtensionOIDs();
    for (String oid : coids) {
      String value = getCertExtensionAsString(cert, oid);
      parts.put(oidToKey(oid), value);
    }

    Set<String> ncoids = cert.getNonCriticalExtensionOIDs();
    for (String oid : ncoids) {
      String value = getCertExtensionAsString(cert, oid);
      parts.put(oidToKey(oid), value);
    }

    MessageDigest md = MessageDigest.getInstance("SHA-1");
    md.update(cert.getEncoded());
    byte[] digest = md.digest();
    parts.put("fingerprintSHA1", new String(Hex.encode(digest)));

    return parts;
  }

  public static String oidToKey(String oid) {
    return "oid_" + oid.replaceAll("\\.", "_");
  }

  public static String getOIDKeyList(Set<String> oids) {
    List<String> keys = new LinkedList<>();
    for (String oid: oids) {
      keys.add("\"" + oidToKey(oid) + "\"");
    }
    return "[" + String.join(",", keys) + "]";
  }

  public static String getCertExtensionAsString(X509Certificate cert, String oid) throws IOException {
    byte [] data = cert.getExtensionValue(oid);
    ASN1OctetString octstr = ASN1OctetString.getInstance(data);
    ASN1Primitive asn1 = ASN1Primitive.fromByteArray(octstr.getOctets());
    return asn1ToString(asn1);
  }

  public static String asn1ToString(ASN1Primitive asn1) {
    if (asn1 instanceof DLSequence) {
      DLSequence dlSequence = (DLSequence) asn1;
      Enumeration<Object> objs = dlSequence.getObjects();
      StringBuilder sb = new StringBuilder();
      while(objs.hasMoreElements()) {
        Object obj = objs.nextElement();
        sb.append(asn1ToString((ASN1Primitive) obj));
      }
      return sb.toString();
    }

    if (asn1 instanceof DERSequence) {
      DERSequence derSequence = (DERSequence) asn1;
      Enumeration<Object> objs = derSequence.getObjects();
      StringBuilder sb = new StringBuilder();
      while(objs.hasMoreElements()) {
        Object obj = objs.nextElement();
        sb.append(asn1ToString((ASN1Primitive) obj));
      }
      return sb.toString();
    }

    if (asn1 instanceof DERIA5String) {
      return DERIA5String.getInstance(asn1).toString();
    }

    if (asn1 instanceof DERPrintableString) {
      return DERPrintableString.getInstance(asn1).toString();
    }

    if (asn1 instanceof  ASN1Boolean) {
      return ((ASN1Boolean) asn1).toString();
    }

    if (asn1 instanceof ASN1Integer) {
      return ((ASN1Integer) asn1).getValue().toString(10);
    }

    if (asn1 instanceof  DERTaggedObject) {
      return asn1ToString(((DERTaggedObject) asn1).getObject());
    }

    if (asn1 instanceof  DEROctetString) {
      return new String(Hex.encode(DEROctetString.getInstance(asn1).getOctets()));
    }

    if (asn1 instanceof DERUTF8String) {
      return DERUTF8String.getInstance(asn1).toString();
    }

    if (asn1 instanceof DERBitString){
      return Integer.toHexString(((DERBitString) asn1).intValue());
    }

    if (asn1 instanceof ASN1ObjectIdentifier) {
      return ((ASN1ObjectIdentifier) asn1).getId();
    }
    return ASN1Dump.dumpAsString(asn1);
  }
}