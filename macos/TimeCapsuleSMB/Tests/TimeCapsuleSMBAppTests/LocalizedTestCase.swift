import Foundation
import XCTest
@testable import TimeCapsuleSMBApp

// Keep UI string assertions independent of the developer's macOS language.
// Volatile preferences affect only this test process, never the user's settings.
class LocalizedTestCase: XCTestCase {
    override func invokeTest() {
        let defaults = UserDefaults.standard
        let originalDomain = defaults.volatileDomain(forName: UserDefaults.argumentDomain)
        let originalLanguage = L10n.currentLanguage
        var testDomain = originalDomain
        testDomain["AppleLanguages"] = ["en"]
        defaults.setVolatileDomain(testDomain, forName: UserDefaults.argumentDomain)
        L10n.apply(language: .english)
        defer {
            L10n.apply(language: originalLanguage)
            defaults.setVolatileDomain(originalDomain, forName: UserDefaults.argumentDomain)
        }
        super.invokeTest()
    }
}
