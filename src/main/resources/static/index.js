(function() {

    'use strict';

    var applicationName = "spring-boot-starter-openssl";
    angular.module(applicationName, []);

    function ApiController($http, $scope) {
        var self = this;

        self.file = null;
        self.fileName = '';

        self.data = { rows: [] };
        self.selectedEntry = {};
        self.type = 'PKCS12';
        self.password = '';

        self.algo = 'RSA';
        self.keysize = '2048';
        self.subjectCer = '';
        self.signAlgoCer = 'SHA256withRSA';
        self.expiryCer = '';

        self.display = true;

        self.browse = function() {
            if (self.file) {
                self.file.click();
            } else {
                self.file = document.getElementById('file');
                self.file.addEventListener('change', self.fileChange);
                self.file.click();
            }
        };

        self.fileChange = function($event) {
            self.fileName = $event.target.value;
            $scope.$apply();
        };

        self.select = function(index) {
            self.selectedEntry = self.data.rows[index];
            if (self.selectedEntry.specs) {
                self.algo = self.selectedEntry.specs.algo;
                self.keysize = self.selectedEntry.specs.keysize;
                self.subjectCer = self.selectedEntry.specs.subjectCer;
                self.signAlgoCer = self.selectedEntry.specs.signAlgoCer;
                self.expiryCer = self.selectedEntry.specs.expiryCer;
            }
        };

        self.checkedAll = function() {
        };

        self.handleSuccess = function(response) {
            self.display = true;
            for (let i = 0; i < response.data.entries.length; i++) {
                self.data.rows.unshift(response.data.entries[i]);
            }
        };

        self.handleError = function(response) {
            self.display = true;
            self.data.rows.unshift({
                type: response.data.status,
                alias: response.data.path,
                value: response.data.error,
                createdAt: response.data.timestamp.substring(0, 19)
            });
            for (let i = 0; i < self.data.rows.length; i++) {
                self.data.rows[i].checked = false;
            }
        };

        self.import = function() {
            if (self.fileName) {
                var formData = new FormData();
                formData.append('type', self.type);
                formData.append('password', self.password);
                formData.append('file', self.file.files[0]);
                self.display = false;
                $http({
                    method: 'POST',
                    url: 'api/v1/decode',
                    headers: { 'Content-Type': undefined },
                    data: formData
                }).then(self.handleSuccess, self.handleError);
            }
        };

        self.generateKeyPair = function() {
            var formData = new FormData();
            formData.append('algo', self.algo);
            formData.append('keysize', self.keysize);
            self.display = false;
            $http({
                method: 'POST',
                url: 'api/v1/keypair',
                headers: { 'Content-Type': undefined },
                data: formData
            }).then(self.handleSuccess, self.handleError);
        };

        self.generateSelfSignCer = function() {
            var formData = new FormData();
            var alias = '';
            if ('KeyPair' == self.selectedEntry.type || 'PrivateKey' == self.selectedEntry.type) {
                alias = self.selectedEntry.alias;
                formData.append('keyPair', self.selectedEntry.value);
            } else {
                alert('Please select KeyPair or PrivateKey to generate self signed certificate');
                return;
            }
            if (self.subjectCer) {
                formData.append('subject', self.subjectCer);
            } else {
                alert('Please enter Subject to generate self signed certificate');
                return;
            }
            if (self.signAlgoCer) {
                formData.append('signatureAlgorithm', self.signAlgoCer);
            }
            if (self.expiryCer) {
                formData.append('expiryDays', self.expiryCer);
            }
            self.display = false;
            $http({
                method: 'POST',
                url: 'api/v1/self-sign-cer',
                headers: { 'Content-Type': undefined },
                data: formData
            }).then(function(response) {
                if (alias) {
                    response.data.entries[0].alias = alias;
                }
                self.handleSuccess(response);
            }, self.handleError);
        };

        self.generateCsr = function() {
            var formData = new FormData();
            var alias = '';
            if ('KeyPair' == self.selectedEntry.type || 'PrivateKey' == self.selectedEntry.type) {
                alias = self.selectedEntry.alias;
                formData.append('keyPair', self.selectedEntry.value);
            } else {
                alert('Please select KeyPair or PrivateKey to generate certificate signing request');
                return;
            }
            if (self.subjectCer) {
                formData.append('subject', self.subjectCer);
            } else {
                alert('Please enter Subject to generate certificate signing request');
                return;
            }
            if (self.signAlgoCer) {
                formData.append('signatureAlgorithm', self.signAlgoCer);
            }
            self.display = false;
            $http({
                method: 'POST',
                url: 'api/v1/csr',
                headers: { 'Content-Type': undefined },
                data: formData
            }).then(function(response) {
                if (alias) {
                    response.data.entries[0].alias = alias;
                }
                self.handleSuccess(response);
            }, self.handleError);
        };

        self.signCsr = function() {
            var formData = new FormData();
            if ('CertificateRequest' == self.selectedEntry.type) {
                formData.append('csr', self.selectedEntry.value);
            } else {
                alert('Please select CertificateRequest to generate certificate');
                return;
            }
            var certificate = '';
            var privateKey = '';
            var keyPair = '';
            for (let i = 0; i < self.data.rows.length; i++) {
                if (self.data.rows[i].checked) {
                    if ('Certificate' == self.data.rows[i].type) {
                        certificate = self.data.rows[i].value;
                    } else if ('KeyPair' == self.data.rows[i].type || 'PrivateKey' == self.data.rows[i].type) {
                        keyPair = self.data.rows[i].value;
                    }
                }
            }
            if (certificate) {
                formData.append('issuerCertificate', certificate);
            } else {
                alert('Issuer Certificate should be checked to sign certificate request');
                return;
            }
            if (keyPair) {
                formData.append('issuerKeyPair', keyPair);
            } else {
                alert('Issuer KeyPair or PrivateKey should be checked to sign certificate request');
                return;
            }
            if (self.signAlgoCer) {
                formData.append('signatureAlgorithm', self.signAlgoCer);
            }
            if (self.expiryCer) {
                formData.append('expiryDays', self.expiryCer);
            }
            self.display = false;
            $http({
                method: 'POST',
                url: 'api/v1/sign-csr',
                headers: { 'Content-Type': undefined },
                data: formData
            }).then(function(response) {
                response.data.entries[0].alias = self.selectedEntry.alias;
                self.handleSuccess(response);
            }, self.handleError);
        };

        self.export = function() {
            var formData = { type: self.type, password: self.password, entries: [] };
            for (let i = 0; i < self.data.rows.length; i++) {
                if (self.data.rows[i].checked && 'Error' != self.data.rows[i].type) {
                    formData.entries.unshift(self.data.rows[i]);
                }
            }
            if (formData.entries.length == 0) {
                alert('No entry checked, only checked entries will be exported');
                return;
            } else if ('Other' == formData.type) {
                var text = 'data:x-application/text,';
                for (let i = 0; i < formData.entries.length; i++) {
                    text = text + escape(formData.entries[i].value) + '\r\n\r\n';
                }
                window.open(text);
                return;
            }
            self.display = false;
            $http({
                method: 'POST',
                url: 'api/v1/encode',
                headers: { 'Content-Type': 'application/json' },
                data: formData,
                responseType: 'arraybuffer'
            }).then(function(response) {
                self.handleSuccess({ data: { entries: [] } });
                var blob = new Blob([response.data], { type: 'application/octet-stream' });
                var objectUrl = URL.createObjectURL(blob);
                window.open(objectUrl);
            }, self.handleError);
        };
    }

    angular.module(applicationName).controller('ApiController', ['$http', '$scope', ApiController]);

}());