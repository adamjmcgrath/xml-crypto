import * as xpath from "xpath";
import * as crypto from "crypto";
import * as xmldom from "@xmldom/xmldom";
import { SignedXml, type SignatureAlgorithm } from "../src/index";
import * as fs from "fs";
import { expect } from "chai";
import * as isDomNode from "@xmldom/is-dom-node";

describe("Signature integration tests", function () {
  function verifySignature(xml, expected, xpath, canonicalizationAlgorithm) {
    const sig = new SignedXml();
    sig.privateKey = fs.readFileSync("./test/static/client.pem");

    xpath.map(function (n) {
      sig.addReference({
        xpath: n,
        digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
        transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
      });
    });

    sig.canonicalizationAlgorithm = canonicalizationAlgorithm;
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.computeSignature(xml);
    const signed = sig.getSignedXml();

    const expectedContent = fs.readFileSync(expected).toString();
    expect(signed, "signature xml different than expected").to.equal(expectedContent);
  }

  it("verify signature", function () {
    const xml =
      '<root><x xmlns="ns"></x><y z_attr="value" a_attr1="foo"></y><z><ns:w ns:attr="value" xmlns:ns="myns"></ns:w></z></root>';
    verifySignature(
      xml,
      "./test/static/integration/expectedVerify.xml",
      ["//*[local-name(.)='x']", "//*[local-name(.)='y']", "//*[local-name(.)='w']"],
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    );
  });

  it("verify signature of complex element", function () {
    const xml =
      "<library>" +
      "<book>" +
      "<name>Harry Potter</name>" +
      '<author id="123456789">' +
      "<firstName>Joanne K</firstName>" +
      "<lastName>Rowling</lastName>" +
      "</author>" +
      "</book>" +
      "</library>";

    verifySignature(
      xml,
      "./test/static/integration/expectedVerifyComplex.xml",
      ["//*[local-name(.)='book']"],
      "http://www.w3.org/2001/10/xml-exc-c14n#",
    );
  });

  it("empty URI reference should consider the whole document", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

    const signature =
      '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">' +
      "<SignedInfo>" +
      '<CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>' +
      '<Reference URI="">' +
      "<Transforms>" +
      '<Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>' +
      "</Transforms>" +
      '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>' +
      "<DigestValue>1tjZsV007JgvE1YFe1C8sMQ+iEg=</DigestValue>" +
      "</Reference>" +
      "</SignedInfo>" +
      "<SignatureValue>FONRc5/nnQE2GMuEV0wK5/ofUJMHH7dzZ6VVd+oHDLfjfWax/lCMzUahJxW1i/dtm9Pl0t2FbJONVd3wwDSZzy6u5uCnj++iWYkRpIEN19RAzEMD1ejfZET8j3db9NeBq2JjrPbw81Fm7qKvte6jGa9ThTTB+1MHFRkC8qjukRM=</SignatureValue>" +
      "</Signature>";

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(xml);

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("add canonicalization if output of transforms will be a node-set rather than an octet stream", function () {
    let xml = fs.readFileSync("./test/static/windows_store_signature.xml", "utf-8");

    /** Make sure that whitespace in the source document is removed --
     * @see xml-crypto issue #23 and post at
     *   http://webservices20.blogspot.co.il/2013/06/validating-windows-mobile-app-store.html
     * This regex is naive but works for this test case; for a more general solution consider
     *   the xmldom-fork-fixed library which can pass {ignoreWhiteSpace: true} into the Dom constructor.
     */
    xml = xml.replace(/>\s*</g, "><");

    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/windows_store_certificate.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("signature with inclusive namespaces", function () {
    const xml = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("signature with inclusive namespaces with unix line separators", function () {
    const xml = fs.readFileSync(
      "./test/static/signature_with_inclusivenamespaces_lines.xml",
      "utf-8",
    );
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("signature with inclusive namespaces with windows line separators", function () {
    const xml = fs.readFileSync(
      "./test/static/signature_with_inclusivenamespaces_lines_windows.xml",
      "utf-8",
    );
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/signature_with_inclusivenamespaces.pem");
    sig.loadSignature(signature);
    const result = sig.checkSignature(childXml ?? "");

    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.equal(1);
  });

  it("should create single root xml document when signing inner node", function () {
    const xml = "<library>" + "<book>" + "<name>Harry Potter</name>" + "</book>" + "</library>";

    const sig = new SignedXml();
    sig.addReference({
      xpath: "//*[local-name(.)='book']",
      digestAlgorithm: "http://www.w3.org/2000/09/xmldsig#sha1",
      transforms: ["http://www.w3.org/2001/10/xml-exc-c14n#"],
    });
    sig.privateKey = fs.readFileSync("./test/static/client.pem");
    sig.canonicalizationAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";
    sig.signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    sig.computeSignature(xml);

    const signed = sig.getSignedXml();

    const doc = new xmldom.DOMParser().parseFromString(signed);

    /*
        Expecting this structure:
        <library>
            <book Id="_0">
                <name>Harry Potter</name>
            </book>
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                    <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                    <Reference URI="#_0">
                        <Transforms><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></Transforms>
                        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                        <DigestValue>cdiS43aFDQMnb3X8yaIUej3+z9Q=</DigestValue>
                    </Reference>
                </SignedInfo>
                <SignatureValue>J79hiSUrKdLOuX....Mthy1M=</SignatureValue>
            </Signature>
        </library>
    */

    expect(doc.documentElement.nodeName, "root node = <library>.").to.equal("library");
    expect(doc.childNodes.length, "only one root node is expected.").to.equal(1);
    expect(
      doc.documentElement.childNodes.length,
      "<library> should have two child nodes : <book> and <Signature>",
    ).to.equal(2);
  });

  const AsyncSignatureAlgorithm = class implements SignatureAlgorithm {
    getAlgorithmName = () => "http://www.w3.org/2000/09/xmldsig#rsa-sha1" as const;
    getSignature = (): never => {
      throw new Error("Not supported");
    };
    verifySignature = (): never => {
      throw new Error("Not supported");
    };
    // Use 1-shot async crypto verify via the optional verifySignatureAsync hook
    verifySignatureAsync = (
      data: string,
      key: crypto.KeyLike,
      sig: string,
      cb: (err: Error | null, result?: boolean) => void,
    ): void => {
      try {
        crypto.verify("RSA-SHA1", Buffer.from(data), key, Buffer.from(sig, "base64"), cb);
      } catch (e) {
        cb(e as Error);
      }
    };
  };

  it("validates signature async with sync crypto", function (done) {
    const xml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);
    sig.checkSignature(childXml ?? "", (err, result) => {
      try {
        expect(err).to.be.null;
        expect(result).to.be.true;
        expect(sig.getSignedReferences().length).to.equal(3);
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("validates signature async with async crypto", function (done) {
    const xml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();

    sig.SignatureAlgorithms = {
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1": AsyncSignatureAlgorithm,
    };

    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);
    sig.checkSignature(childXml ?? "", (err, result) => {
      try {
        expect(err).to.be.null;
        expect(result).to.be.true;
        expect(sig.getSignedReferences().length).to.equal(3);
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("fails async validation for invalid signature with sync crypto", function (done) {
    const xml = fs.readFileSync("./test/static/invalid_signature - signature value.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);
    sig.checkSignature(childXml ?? "", (err, result) => {
      try {
        expect(result).to.be.undefined;
        expect(err).to.be.match(/invalid signature/);
        expect(sig.getSignedReferences().length).to.equal(0);
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("fails async validation for invalid signature with async crypto", function (done) {
    const xml = fs.readFileSync("./test/static/invalid_signature - signature value.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.SignatureAlgorithms = {
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1": AsyncSignatureAlgorithm,
    };
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(signature);
    sig.checkSignature(childXml ?? "", (err, result) => {
      try {
        expect(result).to.be.undefined;
        expect(err).to.be.match(/invalid signature/);
        expect(sig.getSignedReferences().length).to.equal(0);
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("fails async validation for invalid cert with async crypto", function (done) {
    const xml = fs.readFileSync("./test/static/invalid_signature - signature value.xml", "utf-8");
    const doc = new xmldom.DOMParser().parseFromString(xml);
    const childXml = doc.firstChild?.toString();

    const signature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      doc,
    );
    isDomNode.assertIsNodeLike(signature);
    const sig = new SignedXml();
    sig.SignatureAlgorithms = {
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1": AsyncSignatureAlgorithm,
    };
    sig.publicCert = "invalid pem";
    sig.loadSignature(signature);
    sig.checkSignature(childXml ?? "", (err, result) => {
      try {
        expect(result).to.be.undefined;
        expect(err).to.be.match(/error:1E08010C:DECODER routines::unsupported/);
        expect(sig.getSignedReferences().length).to.equal(0);
        done();
      } catch (e) {
        done(e);
      }
    });
  });

  it("clears signed references after error in sync validation", function () {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const invalidXml = fs.readFileSync(
      "./test/static/invalid_signature - signature value.xml",
      "utf-8",
    );

    const validDoc = new xmldom.DOMParser().parseFromString(validXml);
    const validChildXml = validDoc.firstChild?.toString();
    const validSignature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      validDoc,
    );
    isDomNode.assertIsNodeLike(validSignature);

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(validSignature);

    // First validation - should succeed
    const result = sig.checkSignature(validChildXml ?? "");
    expect(result).to.be.true;
    expect(sig.getSignedReferences().length).to.be.greaterThan(0);

    // Second validation with invalid signature and same SignedXml instance
    const invalidDoc = new xmldom.DOMParser().parseFromString(invalidXml);
    const invalidChildXml = invalidDoc.firstChild?.toString();
    const invalidSignature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      invalidDoc,
    );
    isDomNode.assertIsNodeLike(invalidSignature);

    sig.loadSignature(invalidSignature);

    expect(() => sig.checkSignature(invalidChildXml ?? "")).to.throw(/invalid signature/);
    expect(sig.getSignedReferences().length).to.equal(0);
  });

  it("clears signed references after error in async validation", function (done) {
    const validXml = fs.readFileSync("./test/static/valid_signature.xml", "utf-8");
    const invalidXml = fs.readFileSync(
      "./test/static/invalid_signature - signature value.xml",
      "utf-8",
    );

    const validDoc = new xmldom.DOMParser().parseFromString(validXml);
    const validChildXml = validDoc.firstChild?.toString();
    const validSignature = xpath.select1(
      "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
      validDoc,
    );
    isDomNode.assertIsNodeLike(validSignature);

    const sig = new SignedXml();
    sig.publicCert = fs.readFileSync("./test/static/client_public.pem");
    sig.loadSignature(validSignature);

    // First validation - should succeed
    sig.checkSignature(validChildXml ?? "", (err, result) => {
      try {
        expect(err).to.be.null;
        expect(result).to.be.true;
        expect(sig.getSignedReferences().length).to.be.greaterThan(0);

        // Second validation with invalid signature and same SignedXml instance
        const invalidDoc = new xmldom.DOMParser().parseFromString(invalidXml);
        const invalidChildXml = invalidDoc.firstChild?.toString();
        const invalidSignature = xpath.select1(
          "//*//*[local-name(.)='Signature' and namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#']",
          invalidDoc,
        );
        isDomNode.assertIsNodeLike(invalidSignature);

        sig.loadSignature(invalidSignature);
        sig.checkSignature(invalidChildXml ?? "", (err2, result2) => {
          try {
            expect(result2).to.be.undefined;
            expect(err2).to.match(/invalid signature/);
            expect(sig.getSignedReferences().length).to.equal(0);
            done();
          } catch (e) {
            done(e);
          }
        });
      } catch (e) {
        done(e);
      }
    });
  });
});
