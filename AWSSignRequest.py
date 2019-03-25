import sys, os, base64, datetime, hashlib, hmac
from urllib.parse import urlparse

class AWSSignRequest():
    def __init__(self, awsAccessKey, awsSecretKey, awsRegion="us-east-1", awsService="execute-api"):
        self.awsAccessKey = awsAccessKey
        self.awsSecretKey = awsSecretKey
        self.awsRegion = awsRegion
        self.awsService = awsService
        self.algorithm = 'AWS4-HMAC-SHA256'

    def changeRegion(self, awsRegion):
        self.awsRegion = awsRegion

    def changeService(self, awsService):
        self.awsService = awsService

    def signRequest(self, method="GET", endpoint="", payload="", headersToInclude={}):
        # ************* TASK 1: CREATE A CANONICAL REQUEST *************
        # http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

        # Step 1 is to define the verb (GET, POST, etc.)--already done.
        

        # Step 1.5 do not dumb things to get stuff from urls.
        url = urlparse(endpoint)

        # Step 2: Create canonical URI--the part of the URI from domain to query 
        # string (use '/' if no path)
        uri = url.path

        # Step 2.5: Create canonical host....even though amazon doesn't say you have to...
        host = url.netloc

        ## Step 3: Create the canonical query string. In this example, request
        # parameters are passed in the body of the request and the query string
        # is blank.
        
        #untested for positive function.
        #May need to have a prepended `?`
        query = url.query

        # Step 3.5: Create dates for amazon weirdness.
        amazonDate, credentialDate = self.createDates()

        # Step 4: Create the canonical headers. Header names must be trimmed
        # and lowercase, and sorted in code point order from low to high.
        # Note that there is a trailing \n.

        # Step 5: Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers include those that you want to be included in the
        # hash of the request. "Host" and "x-amz-date" are always required.
        # For DynamoDB, content-type and x-amz-target are also required.
        canonicalHeadersString, headersDict, canonicalHeadersListString = self.createCanonicalHeaders(headersToInclude, host, amazonDate)

        # Step 6: Create payload hash. In this example, the payload (body of
        # the request) contains the request parameters.
        payloadHash = hashlib.sha256(payload.encode('utf-8')).hexdigest()
        
        # Step 7: Combine elements to create canonical request
        canonicalRequestItems = [
            method,
            uri,
            query,
            canonicalHeadersString,
            canonicalHeadersListString,
            payloadHash
        ]

        canonicalRequest = self.createCanonicalRequest(canonicalRequestItems)

        canonicalRequestHash = hashlib.sha256(canonicalRequest.encode('utf-8')).hexdigest()
        
        

        credentialScope = self.createCredentialScope(credentialDate)

        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        stringToSign = self.createStringToSign(credentialScope, amazonDate, canonicalRequestHash)
        
        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        signature = self.calculateSignature(credentialDate, stringToSign)

        return self.returnSignedRequestDict(method, endpoint, payload, headersDict, credentialScope, canonicalHeadersListString, signature)

    def returnSignedRequestDict(self, method, endpoint, payload, headersDict, credentialScope, canonicalHeadersListString, signature):
        signedRequest = {
            "method":method,
            "endpoint":endpoint,
            "data":payload,
            "headers":headersDict
        }

        # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        # Put the signature information in a header named Authorization.
        authorizationHeader = self.algorithm + ' ' + 'Credential=' + self.awsAccessKey + '/' + credentialScope + ', ' 
        authorizationHeader = authorizationHeader +  'SignedHeaders=' + canonicalHeadersListString + ', ' + 'Signature=' + signature

        # For DynamoDB, the request can include any headers, but MUST include "host", "x-amz-date",
        # "x-amz-target", "content-type", and "Authorization". Except for the authorization
        # header, the headers must be included in the canonical_headers and signed_headers values, as
        # noted earlier. Order here is not significant.
        # # Python note: The 'host' header is added automatically by the Python 'requests' library.
        signedRequest["headers"]["Authorization"] = authorizationHeader

        return signedRequest    

    def calculateSignature(self, credentialDate, stringToSign):
        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        signingKey = self.getSignatureKey(self.awsSecretKey, credentialDate, self.awsRegion, self.awsService)

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signingKey, stringToSign.encode('utf-8'), hashlib.sha256).hexdigest()

        return signature

    def createCredentialScope(self, credentialDate):
        credentialScopeItems = [
            credentialDate,
            self.awsRegion,
            self.awsService
        ]

        credentialScope = ""
        for item in credentialScopeItems:
            credentialScope = credentialScope + item + '/'

        credentialScope = credentialScope + 'aws4_request'

        return credentialScope

    def createStringToSign(self, credentialScope, amazonDate, canonicalRequestHash):
        stringToSign = ""
        stringToSignItems = [
            self.algorithm,
            amazonDate,
            credentialScope,
            canonicalRequestHash
        ]
        for item in stringToSignItems:
            stringToSign = stringToSign + item + "\n"

        stringToSign = stringToSign[:-1]

        return stringToSign

    def createCanonicalRequest(self, canonicalRequestItems):
        canonicalRequest = ""

        for item in canonicalRequestItems:
            canonicalRequest = canonicalRequest + item + "\n"

        canonicalRequest = canonicalRequest[:-1]

        return canonicalRequest

    def createDates(self):
        now = datetime.datetime.utcnow()
        amazonDate = now.strftime('%Y%m%dT%H%M%SZ')
        credentialDate = now.strftime('%Y%m%d')
        return amazonDate, credentialDate

    def createCanonicalHeaders(self, headersToInclude, host, amazonDate):
        canonicalHeadersString = ""
        canonicalHeadersListString = ""

        if "host" not in headersToInclude:
            headersToInclude["host"] = host
        if "Content-Type" not in headersToInclude:
            headersToInclude["content-type"] = "application/json"
        if 'x-amz-date' not in headersToInclude:
            headersToInclude["x-amz-date"] = amazonDate
        
        for headerName in sorted(list(headersToInclude.keys()), key=str.lower):
            canonicalHeadersString = canonicalHeadersString + headerName.lower() + ":" + headersToInclude[headerName] + "\n"
            canonicalHeadersListString = canonicalHeadersListString + headerName.lower() +";"

        canonicalHeadersListString = canonicalHeadersListString[:-1]

        return canonicalHeadersString, headersToInclude, canonicalHeadersListString

    def sign(self, key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()
    
    def getSignatureKey(self, key, date_stamp, regionName, serviceName):
        kDate = self.sign(('AWS4' + key).encode('utf-8'), date_stamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'aws4_request')
        return kSigning