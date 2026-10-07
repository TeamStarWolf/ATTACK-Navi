// ATTACK-Navi - Copyright (c) 2026 TeamStarWolf
// https://github.com/TeamStarWolf/ATTACK-Navi - MIT License
//
// Karma configuration for `ng test` (angular.json -> test.options.karmaConfig).
//
// The one deliberate departure from the Angular CLI default is
// `failSpecWithNoExpectations: true`: a spec that finishes without running a
// single `expect` is reported as a FAILURE instead of a warning. Two specs in
// this repo passed for months that way (an `if (undefinedField)` guard and an
// HTTP request that was never flushed), so the gate now refuses them.
module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['jasmine', '@angular-devkit/build-angular'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('karma-jasmine-html-reporter'),
      require('karma-coverage'),
      require('@angular-devkit/build-angular/plugins/karma'),
    ],
    client: {
      jasmine: {
        // A spec with zero expectations is a vacuous spec: fail it.
        failSpecWithNoExpectations: true,
      },
      // Leave the Jasmine Spec Runner output visible in the browser.
      clearContext: false,
    },
    jasmineHtmlReporter: {
      suppressAll: true, // removes the duplicated traces
    },
    coverageReporter: {
      dir: require('path').join(__dirname, './coverage/attack-navi'),
      subdir: '.',
      reporters: [{ type: 'html' }, { type: 'text-summary' }],
    },
    reporters: ['progress', 'kjhtml'],
    browsers: ['Chrome'],
    restartOnFileChange: true,
  });
};
