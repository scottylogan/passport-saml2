var dsig = require('xml-dsig'),
    passport = require('passport'),
    querystring = require('querystring'),
    util = require('util'),
    url = require('url'),
    saml2 = require('saml2'),
    xmldom = require('xmldom'),
    zlib = require('zlib');

function Strategy (options) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }

  if (!options.idp || !options.sp) {
    throw new Error("`idp' and `sp' parameters are both required");    
  }


  this.name = 'saml2';

  passport.Strategy.call(this);

  this._idp = new saml2.IdentityProvider(options.idp);
  this._sp = new saml2.ServiceProvider(options.sp);
  var that = this;
  if (options.attributeMap) {
    that._attributeMap = {};
    Object.keys(options.attributeMap).forEach ( function (localName) {
      if (options.attributeMap.hasOwnProperty(localName)) {
        options.attributeMap[localName].forEach(function (attrName) {
          that._attributeMap[attrName] = localName;
        });
      }
    }, that);
  }
  console.error('ATTRIBUTE MAP');
  console.dir(this._attributeMap);
  this._userIdAttr = options.userIdAttr ? options.userIdAttr : false;
  this._userIdProp = options.userIdProp ? options.userIdProp : false;
}

util.inherits(Strategy, passport.Strategy);

Strategy.prototype.initiateRedirect = function initiateRedirect() {
  var message = this._sp.createAuthnRequest(),
      target = this._idp.singleSignOnService,
      type = 'SAMLRequest';
  
  zlib.deflateRaw(message.toString(), function(err, deflated) {
    if (err) {
      throw err;
    }

    var uri = url.parse(target, true);
    uri.query[type] = deflated.toString("base64");
    uri.query.RelayState = Date.now() + "-" + Math.round(Math.random() * 1000000);

    if (this._sp.privateKey) {
      uri.query.SigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

      var toSign = {};
      toSign[type]      = uri.query[type];
      toSign.RelayState = uri.query.RelayState;
      toSign.SigAlg     = uri.query.SigAlg;
      toSign = querystring.stringify(toSign);

      uri.query.Signature = dsig.signatures[uri.query.SigAlg].sign({privateKey: this._sp.privateKey}, toSign);
    }

    return this.redirect(url.format(uri));
  }.bind(this));
};


Strategy.prototype.authenticate = function (req, options) {
  var self = this;
  console.error('AUTHENTICATE');

  if (req.body && req.body.SAMLResponse) {
    
    var xml;
    try {
      xml = (new xmldom.DOMParser()).parseFromString(Buffer(req.body.SAMLResponse, "base64").toString("utf8"));
    } catch (e) {
      console.error('XML Parser Error: ' + e);
      return this.fail('XML Parser Error: ' + e);
    }

    if (this._idp.certificate) {
      var valid;
      try {
        valid = this._idp.verify(xml);
      } catch (e) {
        console.error('Signature Verification:' + e);
        return this.fail('Signature Verification:' + e);
      }
    }

    var message;
    try {
      message = saml2.Protocol.fromXML(xml.documentElement);
    } catch (e) {
      console.error('Assertion Parsing: ' + e);
      return this.fail('Assertion Parsing: ' + e);
    }

    req.samlMessage = message;
    
    if (   !message.Status
        || !message.Status.StatusCode
        || message.Status.StatusCode.Value !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
      console.error('Unknown Status Code');
      return this.fail('Unknown Status Code');
    }

    var conditions = message.Assertion.Conditions
      ? Array.isArray(message.Assertion.Conditions)
        ? message.Assertion.Conditions
        : [message.Assertion.Conditions]
      : [];

    var notBefore, notOnOrAfter;

    for (var i in conditions) {
      if (   conditions[i].NotBefore
          && (notBefore = new Date(conditions[i].NotBefore))
          && !Number.isNaN(notBefore.valueOf())
          && notBefore.valueOf() > Date.now()) {
        console.error('NotBefore Condition failed');
        return this.fail('NotBefore Condition failed');
      }

      if (   conditions[i].NotOnOrAfter
          && (notOnOrAfter = new Date(conditions[i].NotOnOrAfter))
          && !Number.isNaN(notOnOrAfter.valueOf())
          && notOnOrAfter.valueOf() < Date.now()) {
        console.error('NotOnOrAfter Condition failed');
        return this.fail('NotOnOrAfter Condition failed');
      }
    }

    var nameId;
    if (   message.Assertion
        && message.Assertion.Subject
        && message.Assertion.Subject.NameID) {
      nameId = message.Assertion.Subject.NameID._content;
    }

    if (!nameId) {
      console.error('No NameID');
      return this.fail('No NameID');
    }

    var attributes;
    if (   req.samlMessage.Assertion
        && req.samlMessage.Assertion.AttributeStatement
        && req.samlMessage.Assertion.AttributeStatement.Attribute) {
      attributes = req.samlMessage.Assertion.AttributeStatement.Attribute;

      if (!Array.isArray(attributes)) {
        attributes = [attributes];
      }

      console.error('ATTRIBUTES');
      console.dir(attributes);
      
      var user = {};
      if (this._attributeMap) {
        
        attributes.forEach(function (attr) {
          console.error('ATTRIBUTE: ' + attr.Name + '/' + attr.FriendlyName);
          var name = this._attributeMap[attr.Name] || this._attributeMap[attr.FriendlyName] || false,
              values = (Array.isArray(attr.AttributeValue) ? attr.AttributeValue : [ attr.AttributeValue ]).map(function (val) {
                return val._content;
              }),
              value = values.join(';');


          if (name) {
            console.error('PROPERTY: ' + name);
            console.dir(value);
            user[name] = value;
            if (values.length > 1) {
              user._values = user._values || [];
              user._values[name] = values;
            }
          }
        }, this);
      } else {
        console.error('NO ATTRIBUTE MAP!!!');
      }
    }

    if (this._userIdAttr && this._userIdProp) {
      var ids = this._userIdAttr.filter(function (idAttr) {
        return user._values[idAttr] ? user._values[idAttr][0] : 
          user[idAttr] ? user[idAttr] : false;
      });

      if (ids.length > 0) {
        user[this._userIdProp] = user[ids[0]];
      }
    }
    
    console.error('SUCCESS!!!');
    console.dir(user);

    return this.success(user);
  } else {
    // Initiate new SAML authentication request
    console.error('REDIRECTING!!!');
    this.initiateRedirect();
  }
};

Strategy.prototype.logout = function(req, callback) {
  this._saml.getLogoutUrl(req, callback);
};

module.exports = Strategy;
