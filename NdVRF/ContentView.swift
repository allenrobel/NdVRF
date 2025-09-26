import SwiftUI
import Foundation
import Combine

// MARK: - Main App
@main
struct NexusDashboardApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unified)
    }
}

// MARK: - Models
// Helper to flexibly decode booleans that may arrive as Bool, String, or Int
enum FlexibleBool: Codable, Hashable {
    case bool(Bool)
    case string(String)
    case int(Int)

    var boolValue: Bool? {
        switch self {
        case .bool(let b):
            return b
        case .int(let i):
            return i == 0 ? false : true
        case .string(let s):
            let normalized = s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            if ["true", "yes", "y", "1", "enabled", "on"].contains(normalized) { return true }
            if ["false", "no", "n", "0", "disabled", "off"].contains(normalized) { return false }
            return nil
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let b = try? container.decode(Bool.self) {
            self = .bool(b)
            return
        }
        if let i = try? container.decode(Int.self) {
            self = .int(i)
            return
        }
        if let s = try? container.decode(String.self) {
            self = .string(s)
            return
        }
        throw DecodingError.typeMismatch(FlexibleBool.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Expected Bool, Int, or String for FlexibleBool"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .bool(let b):
            try container.encode(b)
        case .int(let i):
            try container.encode(i)
        case .string(let s):
            try container.encode(s)
        }
    }
}

// Helper to flexibly decode integers that may arrive as Int, String, Double, or Bool
enum FlexibleInt: Codable, Hashable {
    case int(Int)
    case string(String)
    case double(Double)
    case bool(Bool)

    var intValue: Int? {
        switch self {
        case .int(let i):
            return i
        case .double(let d):
            return Int(d)
        case .string(let s):
            let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
            if let i = Int(trimmed) { return i }
            if let d = Double(trimmed) { return Int(d) }
            return nil
        case .bool(let b):
            return b ? 1 : 0
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let i = try? container.decode(Int.self) {
            self = .int(i)
            return
        }
        if let d = try? container.decode(Double.self) {
            self = .double(d)
            return
        }
        if let s = try? container.decode(String.self) {
            self = .string(s)
            return
        }
        if let b = try? container.decode(Bool.self) {
            self = .bool(b)
            return
        }
        throw DecodingError.typeMismatch(FlexibleInt.self, DecodingError.Context(codingPath: decoder.codingPath, debugDescription: "Expected Int, Double, String, or Bool for FlexibleInt"))
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
            case .int(let i): try container.encode(i)
            case .double(let d): try container.encode(d)
            case .string(let s): try container.encode(s)
            case .bool(let b): try container.encode(b)
        }
    }
}

struct LoginRequest: Codable {
    let domain: String
    let userName: String
    let userPasswd: String
}

struct LoginResponse: Codable {
    let token: String?
    let status: String?
    let message: String?
}

struct VRF: Codable, Identifiable, Hashable {
    let id = UUID()
    let fabric: String?
    let vrfName: String
    let vrfTemplate: String?
    let vrfExtensionTemplate: String?
    let vrfId: Int?
    let serviceVrfTemplate: String?
    let source: String?
    let vrfTemplateConfig: String?

    // Computed property for parsed template config
    var parsedTemplateConfig: VRFTemplateConfig? {
        guard let configString = vrfTemplateConfig,
              let data = configString.data(using: .utf8) else { return nil }
        do {
            return try JSONDecoder().decode(VRFTemplateConfig.self, from: data)
        } catch {
            print("Failed to decode VRFTemplateConfig:", error)
            return nil
        }
    }

    // Computed property for description (from parsed config)
    var vrfDescription: String? {
        return parsedTemplateConfig?.vrfDescription
    }
    
    // Hashable conformance
    func hash(into hasher: inout Hasher) {
        hasher.combine(id)
        hasher.combine(vrfName)
        hasher.combine(vrfId)
    }
    
    static func == (lhs: VRF, rhs: VRF) -> Bool {
        return lhs.id == rhs.id
    }
    
    enum CodingKeys: String, CodingKey {
        case fabric
        case vrfName
        case vrfTemplate
        case vrfExtensionTemplate
        case vrfId
        case serviceVrfTemplate
        case source
        case vrfTemplateConfig
    }
}

struct VRFTemplateConfig: Codable, Hashable {
    let advertiseDefaultRouteFlagRaw: FlexibleBool?
    var advertiseDefaultRouteFlag: Bool? {
        advertiseDefaultRouteFlagRaw?.boolValue
    }
    let advertiseHostRouteFlagRaw: FlexibleBool?
    var advertiseHostRouteFlag: Bool? {
        advertiseHostRouteFlagRaw?.boolValue
    }
    // Computed booleans from flexible decoding
    var disableRtAuto: Bool? { disableRtAutoRaw?.boolValue }
    var ipv6LinkLocalFlag: Bool? { ipv6LinkLocalFlagRaw?.boolValue }
    var enableNetflow: Bool? { enableNetflowRaw?.boolValue }
    var isRPAbsent: Bool? { isRPAbsentRaw?.boolValue }
    var isRPExternal: Bool? { isRPExternalRaw?.boolValue }
    var configureStaticDefaultRouteFlag: Bool? { configureStaticDefaultRouteFlagRaw?.boolValue }
    var trmBGWMSiteEnabled: Bool? { trmBGWMSiteEnabledRaw?.boolValue }
    var trmEnabled: Bool? { trmEnabledRaw?.boolValue }
    
    // Computed integers from flexible decoding
    var bgpPasswordKeyType: Int? { bgpPasswordKeyTypeRaw?.intValue }
    var tag: Int? { tagRaw?.intValue }
    var maxBgpPaths: Int? { maxBgpPathsRaw?.intValue }
    var maxIbgpPaths: Int? { maxIbgpPathsRaw?.intValue }
    var mtu: Int? { mtuRaw?.intValue }
    var vrfVlanId: Int? { vrfVlanIdRaw?.intValue }
    var vrfSegmentId: Int? { vrfSegmentIdRaw?.intValue }
    
    let bgpPassword: String?
    let bgpPasswordKeyTypeRaw: FlexibleInt?
    let disableRtAutoRaw: FlexibleBool?
    let routeTargetExportEvpn: String?
    let routeTargetExportMvpn: String?
    let routeTargetExport: String?
    let routeTargetImportEvpn: String?
    let routeTargetImportMvpn: String?
    let routeTargetImport: String?
    let ipv6LinkLocalFlagRaw: FlexibleBool?
    let tagRaw: FlexibleInt?
    let maxBgpPathsRaw: FlexibleInt?
    let maxIbgpPathsRaw: FlexibleInt?
    let enableNetflowRaw: FlexibleBool?
    let netflowMonitor: String?
    let isRPAbsentRaw: FlexibleBool?
    let multicastGroup: String?
    let vrfRouteMap: String?
    let rpAddress: String?
    let isRPExternalRaw: FlexibleBool?
    let loopbackNumber: String?
    let configureStaticDefaultRouteFlagRaw: FlexibleBool?
    let trmBGWMSiteEnabledRaw: FlexibleBool?
    let trmEnabledRaw: FlexibleBool?
    let l3VniMcastGroup: String?
    let vrfVlanIdRaw: FlexibleInt?
    let vrfDescription: String?
    let vrfSegmentIdRaw: FlexibleInt?
    let mtuRaw: FlexibleInt?
    let vrfIntfDescription: String?
    let vrfName: String?
    let vrfVlanName: String?
    
    enum CodingKeys: String, CodingKey {
        case advertiseDefaultRouteFlagRaw = "advertiseDefaultRouteFlag"
        case advertiseHostRouteFlagRaw = "advertiseHostRouteFlag"
        case bgpPassword
        case bgpPasswordKeyTypeRaw = "bgpPasswordKeyType"
        case disableRtAutoRaw = "disableRtAuto"
        case routeTargetExportEvpn
        case routeTargetExportMvpn
        case routeTargetExport
        case routeTargetImportEvpn
        case routeTargetImportMvpn
        case routeTargetImport
        case ipv6LinkLocalFlagRaw = "ipv6LinkLocalFlag"
        case tagRaw = "tag"
        case maxBgpPathsRaw = "maxBgpPaths"
        case maxIbgpPathsRaw = "maxIbgpPaths"
        case enableNetflowRaw = "ENABLE_NETFLOW"
        case netflowMonitor = "NETFLOW_MONITOR"
        case isRPAbsentRaw = "isRPAbsent"
        case multicastGroup
        case vrfRouteMap
        case rpAddress
        case isRPExternalRaw = "isRPExternal"
        case loopbackNumber
        case configureStaticDefaultRouteFlagRaw = "configureStaticDefaultRouteFlag"
        case trmBGWMSiteEnabledRaw = "trmBGWMSiteEnabled"
        case trmEnabledRaw = "trmEnabled"
        case l3VniMcastGroup = "L3VniMcastGroup"
        case vrfVlanIdRaw = "vrfVlanId"
        case vrfDescription
        case vrfSegmentIdRaw = "vrfSegmentId"
        case mtuRaw = "mtu"
        case vrfIntfDescription
        case vrfName
        case vrfVlanName
    }
}

struct VRFListResponse: Codable {
    let vrfs: [VRF]?
    let message: String?
    let error: String?
}

// MARK: - Network Manager
@MainActor
class NetworkManager: ObservableObject {
    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var isLoggedIn = false
    @Published var vrfs: [VRF] = []
    @Published var selectedVRF: VRF?
    
    private var authToken: String?
    private var baseURL: String?
    private var urlSession: URLSession
    
    init() {
        // Create a custom URL session that can handle untrusted certificates
        self.urlSession = URLSession.shared
    }
    
    func configureURLSession(allowUntrustedCertificates: Bool) {
        if allowUntrustedCertificates {
            let configuration = URLSessionConfiguration.default
            urlSession = URLSession(
                configuration: configuration,
                delegate: UntrustedCertificateDelegate(),
                delegateQueue: nil
            )
        } else {
            urlSession = URLSession.shared
        }
    }
    
    func login(serverIP: String, username: String, password: String, domain: String = "local", allowUntrustedCertificates: Bool = false) async {
        isLoading = true
        errorMessage = nil
        
        // Configure URL session based on certificate trust setting
        configureURLSession(allowUntrustedCertificates: allowUntrustedCertificates)
        
        guard let url = URL(string: "https://\(serverIP)/login") else {
            errorMessage = "Invalid server IP address"
            isLoading = false
            return
        }
        
        baseURL = "https://\(serverIP)"
        
        let loginRequest = LoginRequest(
            domain: domain,
            userName: username,
            userPasswd: password
        )
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        
        do {
            let jsonData = try JSONEncoder().encode(loginRequest)
            request.httpBody = jsonData
            
            let (data, response) = try await urlSession.data(for: request)
            
            if let httpResponse = response as? HTTPURLResponse {
                print("Login response status: \(httpResponse.statusCode)")
                
                if httpResponse.statusCode == 200 {
                    // Debug: Print response details
                    print("Login successful - Status: \(httpResponse.statusCode)")
                    print("Headers: \(httpResponse.allHeaderFields)")
                    
                    // First, try to extract from cookies
                    var tokenFound = false
                    
                    // Check for Set-Cookie headers
                    if let cookies = HTTPCookieStorage.shared.cookies(for: url) {
                        for cookie in cookies {
                            print("Cookie: \(cookie.name) = \(cookie.value)")
                            // Common Cisco cookie names
                            if cookie.name.lowercased().contains("session") ||
                               cookie.name.lowercased().contains("token") ||
                               cookie.name.lowercased().contains("auth") ||
                               cookie.name == "Djf" ||
                               cookie.name == "JSESSIONID" {
                                authToken = cookie.value
                                isLoggedIn = true
                                tokenFound = true
                                print("Found auth cookie: \(cookie.name)")
                                break
                            }
                        }
                    }
                    
                    // If no cookie found, check response body
                    if !tokenFound {
                        let responseString = String(data: data, encoding: .utf8) ?? ""
                        print("Response body: \(responseString)")
                        
                        // Try to parse as JSON
                        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                            print("JSON response: \(json)")
                            
                            // Check for various token field names
                            if let token = json["token"] as? String ??
                                          json["sessionId"] as? String ??
                                          json["authToken"] as? String ??
                                          json["access_token"] as? String {
                                authToken = token
                                isLoggedIn = true
                                tokenFound = true
                                print("Found token in JSON response")
                            }
                        }
                    }
                    
                    // If still no token found, assume cookie-based auth is working
                    if !tokenFound {
                        // For some APIs, successful login just means cookies are set
                        // and we don't need an explicit token
                        authToken = "cookie-based-auth"
                        isLoggedIn = true
                        tokenFound = true
                        print("Assuming cookie-based authentication")
                    }
                    
                    if !tokenFound {
                        errorMessage = "Login successful but failed to extract authentication token. Response: \(String(data: data, encoding: .utf8) ?? "No response")"
                    }
                } else {
                    let responseString = String(data: data, encoding: .utf8) ?? "Unknown error"
                    errorMessage = "Login failed: HTTP \(httpResponse.statusCode) - \(responseString)"
                }
            }
        } catch {
            errorMessage = "Network error: \(error.localizedDescription)"
        }
        
        isLoading = false
    }
    
    func fetchVRFs(fabricName: String) async {
        guard isLoggedIn, let baseURL = baseURL else {
            errorMessage = "Not logged in"
            return
        }
        
        guard !fabricName.isEmpty else {
            errorMessage = "Fabric name is required"
            return
        }
        
        isLoading = true
        errorMessage = nil
        selectedVRF = nil // Clear selection when fetching new VRFs
        
        let endpoint = "/appcenter/cisco/ndfc/api/v1/lan-fabric/rest/top-down/fabrics/\(fabricName)/vrfs"
        guard let url = URL(string: baseURL + endpoint) else {
            errorMessage = "Invalid URL"
            isLoading = false
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Add authentication headers
        if let token = authToken {
            if token != "cookie-based-auth" {
                // Use token-based auth
                request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            }
            // For cookie-based auth, cookies are automatically included
        }
        
        do {
            let (data, response) = try await urlSession.data(for: request)
            // Right after you receive `data` in fetchVRFs:
            if let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]],
               let first = json.first {
                if let rawConfig = first["vrfTemplateConfig"] {
                    print("vrfTemplateConfig raw type:", type(of: rawConfig), "value:", rawConfig)
                }
            }
            if let httpResponse = response as? HTTPURLResponse {
                print("VRF fetch response status: \(httpResponse.statusCode)")
                
                if httpResponse.statusCode == 200 {
                    // Try to decode as array of VRFs directly
                    if let vrfArray = try? JSONDecoder().decode([VRF].self, from: data) {
                        vrfs = vrfArray
                        print("vrfs: \(vrfs[0].vrfTemplateConfig ?? "Unable to parse vrfTemplateConfig")")
                    } else {
                        // Try to decode as wrapped response
                        if let vrfResponse = try? JSONDecoder().decode(VRFListResponse.self, from: data),
                           let vrfArray = vrfResponse.vrfs {
                            vrfs = vrfArray
                        } else {
                            // Try to parse as generic JSON and extract VRF info
                            if let json = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] {
                                vrfs = parseVRFsFromJSON(json)
                            } else {
                                let responseString = String(data: data, encoding: .utf8) ?? "Unknown response"
                                errorMessage = "Failed to parse VRF response: \(responseString)"
                            }
                        }
                    }
                } else {
                    let responseString = String(data: data, encoding: .utf8) ?? "Unknown error"
                    errorMessage = "Failed to fetch VRFs: HTTP \(httpResponse.statusCode) - \(responseString)"
                }
            }
        } catch {
            errorMessage = "Network error: \(error.localizedDescription)"
        }
        
        isLoading = false
    }
    
    func logout() {
        authToken = nil
        isLoggedIn = false
        vrfs = []
        selectedVRF = nil
        errorMessage = nil
    }
    
    // MARK: - Helper Methods
    private func extractSessionToken(from cookies: String) -> String? {
        let cookiePairs = cookies.components(separatedBy: ";")
        for pair in cookiePairs {
            let components = pair.components(separatedBy: "=")
            if components.count == 2 {
                let name = components[0].trimmingCharacters(in: .whitespaces)
                let value = components[1].trimmingCharacters(in: .whitespaces)
                if name.lowercased().contains("session") || name.lowercased().contains("token") {
                    return value
                }
            }
        }
        return nil
    }
    
    private func parseVRFsFromJSON(_ json: [[String: Any]]) -> [VRF] {
        var vrfs: [VRF] = []
        
        for item in json {
            let fabric = item["fabric"] as? String
            let vrfName = item["vrfName"] as? String ?? item["name"] as? String ?? "Unknown"
            let vrfTemplate = item["vrfTemplate"] as? String
            let vrfExtensionTemplate = item["vrfExtensionTemplate"] as? String
            let vrfId = item["vrfId"] as? Int ?? item["id"] as? Int
            let serviceVrfTemplate = item["serviceVrfTemplate"] as? String
            let source = item["source"] as? String
            let vrfTemplateConfig = item["vrfTemplateConfig"] as? String
            
            let vrf = VRF(
                fabric: fabric,
                vrfName: vrfName,
                vrfTemplate: vrfTemplate,
                vrfExtensionTemplate: vrfExtensionTemplate,
                vrfId: vrfId,
                serviceVrfTemplate: serviceVrfTemplate,
                source: source,
                vrfTemplateConfig: vrfTemplateConfig
            )
            vrfs.append(vrf)
        }
        
        return vrfs
    }
}

// MARK: - SSL Certificate Delegate
class UntrustedCertificateDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Accept any certificate (including self-signed and invalid ones)
        let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, credential)
    }
}

// MARK: - Views
struct ContentView: View {
    @StateObject private var networkManager = NetworkManager()
    @State private var serverIP = ""
    @State private var username = ""
    @State private var password = ""
    @State private var domain = "local"
    @State private var fabricName = ""
    @State private var allowUntrustedCertificates = true
    @State private var showingAlert = false
    
    var body: some View {
        Group {
            if !networkManager.isLoggedIn {
                // Login View
                loginView
            } else {
                // Main VRF Interface with Master-Detail Layout
                VRFMasterDetailView(
                    networkManager: networkManager,
                    serverIP: serverIP,
                    username: username,
                    fabricName: $fabricName
                )
            }
        }
        .alert("Error", isPresented: $showingAlert) {
            Button("OK") { }
        } message: {
            Text(networkManager.errorMessage ?? "Unknown error")
        }
        .onChange(of: networkManager.errorMessage) {
            showingAlert = networkManager.errorMessage != nil
        }
    }
    
    private var loginView: some View {
        VStack(spacing: 20) {
            // Header
            VStack {
                Image(systemName: "network")
                    .font(.system(size: 48))
                    .foregroundColor(.blue)
                
                Text("Cisco Nexus Dashboard")
                    .font(.title)
                    .fontWeight(.bold)
                
                Text("VRF Viewer")
                    .font(.headline)
                    .foregroundColor(.secondary)
            }
            .padding(.top)
            
            Divider()
            
            // Login Form
            loginForm
            
            Spacer()
        }
        .padding()
        .frame(minWidth: 500, minHeight: 400)
    }
    
    private var loginForm: some View {
        VStack(spacing: 16) {
            Text("Login to Nexus Dashboard")
                .font(.headline)
            
            Group {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Server IP Address")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    TextField("Enter server IP", text: $serverIP)
                        .textFieldStyle(.roundedBorder)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Username")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    TextField("Enter username", text: $username)
                        .textFieldStyle(.roundedBorder)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Password")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    SecureField("Enter password", text: $password)
                        .textFieldStyle(.roundedBorder)
                }
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Domain")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    TextField("Domain", text: $domain)
                        .textFieldStyle(.roundedBorder)
                }
                
                // SSL Certificate Option
                VStack(alignment: .leading, spacing: 8) {
                    Toggle("Allow untrusted certificates", isOn: $allowUntrustedCertificates)
                        .toggleStyle(.checkbox)
                    
                    Text("Enable this option to connect to servers with self-signed or invalid SSL certificates")
                        .font(.caption)
                        .foregroundColor(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            
            Button(action: {
                Task {
                    await networkManager.login(
                        serverIP: serverIP,
                        username: username,
                        password: password,
                        domain: domain,
                        allowUntrustedCertificates: allowUntrustedCertificates
                    )
                }
            }) {
                HStack {
                    if networkManager.isLoading {
                        ProgressView()
                            .scaleEffect(0.8)
                    }
                    Text("Login")
                }
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .disabled(networkManager.isLoading || serverIP.isEmpty || username.isEmpty || password.isEmpty)
        }
        .padding()
        .background(Color(NSColor.controlBackgroundColor))
        .cornerRadius(12)
    }
}

// MARK: - Master-Detail VRF View
struct VRFMasterDetailView: View {
    @ObservedObject var networkManager: NetworkManager
    let serverIP: String
    let username: String
    @Binding var fabricName: String
    
    var body: some View {
        NavigationView {
            // Left Sidebar - VRF List
            VRFSidebarView(networkManager: networkManager, fabricName: $fabricName)
                .frame(minWidth: 250, maxWidth: 400)
            
            // Right Detail View
            VRFDetailView(
                selectedVRF: networkManager.selectedVRF,
                serverIP: serverIP,
                username: username,
                fabricName: fabricName
            )
            .frame(minWidth: 400)
        }
        .navigationTitle("VRF Management")
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button("Logout") {
                    networkManager.logout()
                }
            }
        }
    }
}

// MARK: - VRF Sidebar View
struct VRFSidebarView: View {
    @ObservedObject var networkManager: NetworkManager
    @Binding var fabricName: String
    
    var body: some View {
        VStack(spacing: 0) {
            // Header Section
            VStack(spacing: 12) {
                // Fabric Input
                VStack(alignment: .leading, spacing: 8) {
                    Text("Fabric Configuration")
                        .font(.headline)
                    
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Fabric Name")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        
                        HStack {
                            TextField("Enter fabric name", text: $fabricName)
                                .textFieldStyle(.roundedBorder)
                            
                            Button(action: {
                                Task {
                                    await networkManager.fetchVRFs(fabricName: fabricName)
                                }
                            }) {
                                if networkManager.isLoading {
                                    ProgressView()
                                        .scaleEffect(0.8)
                                } else {
                                    Image(systemName: "arrow.clockwise")
                                }
                            }
                            .buttonStyle(.bordered)
                            .disabled(networkManager.isLoading || fabricName.isEmpty)
                        }
                    }
                }
                
                // VRF Count
                HStack {
                    Text("VRFs")
                        .font(.headline)
                    
                    Spacer()
                    
                    Text("\(networkManager.vrfs.count)")
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(8)
                }
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            
            Divider()
            
            // VRF List
            if networkManager.vrfs.isEmpty {
                VStack(spacing: 16) {
                    Spacer()
                    
                    Image(systemName: "network.slash")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    
                    Text("No VRFs")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    
                    Text("Enter a fabric name and click refresh to load VRFs")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                    
                    Spacer()
                }
                .frame(maxWidth: .infinity)
            } else {
                List(
                    networkManager.vrfs,
                    selection: Binding(
                        get: { networkManager.selectedVRF },
                        set: { newValue in
                            // Defer to next run loop to avoid publishing during view updates
                            DispatchQueue.main.async {
                                networkManager.selectedVRF = newValue
                            }
                        }
                    )
                ) { vrf in
                    VRFListRowView(vrf: vrf)
                        .tag(vrf)
                }
                .listStyle(.sidebar)
            }
        }
    }
}

// MARK: - VRF List Row View
struct VRFListRowView: View {
    let vrf: VRF
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(vrf.vrfName)
                    .font(.headline)
                    .foregroundColor(.primary)
                
                Spacer()
                
                if let vrfId = vrf.vrfId {
                    Text("ID: \(vrfId)")
                        .font(.caption)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.blue.opacity(0.1))
                        .cornerRadius(4)
                }
            }
            
            if let description = vrf.vrfDescription, !description.isEmpty {
                Text(description)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
        }
        .padding(.vertical, 4)
    }
}

// MARK: - VRF Detail View
struct VRFDetailView: View {
    let selectedVRF: VRF?
    let serverIP: String
    let username: String
    let fabricName: String
    
    var body: some View {
        Group {
            if let vrf = selectedVRF {
                ScrollView {
                    VStack(alignment: .leading, spacing: 20) {
                        // Header
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Text(vrf.vrfName)
                                    .font(.largeTitle)
                                    .fontWeight(.bold)
                                
                                Spacer()
                                
                                if let vrfId = vrf.vrfId {
                                    Text("ID: \(vrfId)")
                                        .font(.title2)
                                        .padding(.horizontal, 12)
                                        .padding(.vertical, 6)
                                        .background(Color.blue.opacity(0.1))
                                        .cornerRadius(8)
                                }
                            }
                            
                            if let description = vrf.vrfDescription, !description.isEmpty {
                                Text(description)
                                    .font(.headline)
                                    .foregroundColor(.secondary)
                            }
                        }
                        
                        Divider()
                        
                        // Basic Information
                        VRFDetailSection(title: "Basic Information", icon: "info.circle") {
                            VRFDetailRow(label: "VRF Name", value: vrf.vrfName)
                            
                            if let vrfId = vrf.vrfId {
                                VRFDetailRow(label: "VRF ID", value: "\(vrfId)")
                            }
                            
                            if let fabric = vrf.fabric, !fabric.isEmpty {
                                VRFDetailRow(label: "Fabric", value: fabric)
                            }
                            
                            if let description = vrf.vrfDescription, !description.isEmpty {
                                VRFDetailRow(label: "Description", value: description)
                            }
                        }
                        
                        // Configuration Details from Template
                        if let config = vrf.parsedTemplateConfig {
                            VRFDetailSection(title: "Configuration Details", icon: "gearshape") {
                                if let description = config.vrfDescription, !description.isEmpty {
                                    VRFDetailRow(label: "Description", value: description)
                                }
                                
                                if let segmentId = config.vrfSegmentId {
                                    VRFDetailRow(label: "Segment ID", value: "\(segmentId)")
                                }
                                
                                if let vlanId = config.vrfVlanId {
                                    VRFDetailRow(label: "VLAN ID", value: "\(vlanId)")
                                }
                                
                                if let mtu = config.mtu {
                                    VRFDetailRow(label: "MTU", value: "\(mtu)")
                                }
                                
                                if let tag = config.tag {
                                    VRFDetailRow(label: "Tag", value: "\(tag)")
                                }
                            }
                        }
                        
                        // Network Configuration
                        if let config = vrf.parsedTemplateConfig {
                            VRFDetailSection(title: "Network Configuration", icon: "network") {
                                if let defaultRoute = config.advertiseDefaultRouteFlag {
                                    VRFDetailRow(label: "Advertise Default Route", value: defaultRoute ? "Enabled" : "Disabled")
                                }
                                if let advertiseHost = config.advertiseHostRouteFlag {
                                    VRFDetailRow(label: "Advertise Host Route", value: advertiseHost ? "Enabled" : "Disabled")
                                }
                                
                                if let ipv6LinkLocal = config.ipv6LinkLocalFlag {
                                    VRFDetailRow(label: "IPv6 Link Local", value: ipv6LinkLocal ? "Enabled" : "Disabled")
                                }
                                
                                if let staticDefault = config.configureStaticDefaultRouteFlag {
                                    VRFDetailRow(label: "Static Default Route", value: staticDefault ? "Enabled" : "Disabled")
                                }
                                
                                if let routeMap = config.vrfRouteMap, !routeMap.isEmpty {
                                    VRFDetailRow(label: "Route Map", value: routeMap)
                                }
                            }
                        }
                        
                        // BGP Configuration
                        if let config = vrf.parsedTemplateConfig {
                            VRFDetailSection(title: "BGP Configuration", icon: "arrow.branch") {
                                if let maxPaths = config.maxBgpPaths {
                                    VRFDetailRow(label: "Max BGP Paths", value: "\(maxPaths)")
                                }
                                
                                if let maxIbgpPaths = config.maxIbgpPaths {
                                    VRFDetailRow(label: "Max iBGP Paths", value: "\(maxIbgpPaths)")
                                }
                                
                                if let disableRtAuto = config.disableRtAuto {
                                    VRFDetailRow(label: "Disable RT Auto", value: disableRtAuto ? "Yes" : "No")
                                }
                            }
                        }
                        
                        // Route Targets
                        if let config = vrf.parsedTemplateConfig {
                            VRFDetailSection(title: "Route Targets", icon: "arrow.triangle.branch") {
                                if let rtExport = config.routeTargetExport, !rtExport.isEmpty {
                                    VRFDetailRow(label: "RT Export", value: rtExport)
                                }
                                
                                if let rtImport = config.routeTargetImport, !rtImport.isEmpty {
                                    VRFDetailRow(label: "RT Import", value: rtImport)
                                }
                                
                                if let rtExportEvpn = config.routeTargetExportEvpn, !rtExportEvpn.isEmpty {
                                    VRFDetailRow(label: "RT Export EVPN", value: rtExportEvpn)
                                }
                                
                                if let rtImportEvpn = config.routeTargetImportEvpn, !rtImportEvpn.isEmpty {
                                    VRFDetailRow(label: "RT Import EVPN", value: rtImportEvpn)
                                }
                            }
                        }
                        
                        // Multicast Configuration
                        if let config = vrf.parsedTemplateConfig {
                            VRFDetailSection(title: "Multicast Configuration", icon: "dot.radiowaves.left.and.right") {
                                if let trmEnabled = config.trmEnabled {
                                    VRFDetailRow(label: "TRM Enabled", value: trmEnabled ? "Yes" : "No")
                                }
                                
                                if let trmBGWEnabled = config.trmBGWMSiteEnabled {
                                    VRFDetailRow(label: "TRM BGW Site", value: trmBGWEnabled ? "Enabled" : "Disabled")
                                }
                                
                                if let mcastGroup = config.multicastGroup, !mcastGroup.isEmpty {
                                    VRFDetailRow(label: "Multicast Group", value: mcastGroup)
                                }
                                
                                if let l3VniGroup = config.l3VniMcastGroup, !l3VniGroup.isEmpty {
                                    VRFDetailRow(label: "L3 VNI Multicast Group", value: l3VniGroup)
                                }
                                
                                if let rpAddress = config.rpAddress, !rpAddress.isEmpty {
                                    VRFDetailRow(label: "RP Address", value: rpAddress)
                                }
                                
                                if let isRPExternal = config.isRPExternal {
                                    VRFDetailRow(label: "RP External", value: isRPExternal ? "Yes" : "No")
                                }
                                
                                if let isRPAbsent = config.isRPAbsent {
                                    VRFDetailRow(label: "RP Absent", value: isRPAbsent ? "Yes" : "No")
                                }
                            }
                        }
                        
                        // Monitoring Configuration
                        if let config = vrf.parsedTemplateConfig {
                            VRFDetailSection(title: "Monitoring", icon: "chart.line.uptrend.xyaxis") {
                                if let netflowEnabled = config.enableNetflow {
                                    VRFDetailRow(label: "NetFlow", value: netflowEnabled ? "Enabled" : "Disabled")
                                }
                                
                                if let netflowMonitor = config.netflowMonitor, !netflowMonitor.isEmpty {
                                    VRFDetailRow(label: "NetFlow Monitor", value: netflowMonitor)
                                }
                            }
                        }
                        
                        // Template Information
                        VRFDetailSection(title: "Template Configuration", icon: "doc.text") {
                            if let vrfTemplate = vrf.vrfTemplate, !vrfTemplate.isEmpty {
                                VRFDetailRow(label: "VRF Template", value: vrfTemplate)
                            }
                            
                            if let extensionTemplate = vrf.vrfExtensionTemplate, !extensionTemplate.isEmpty {
                                VRFDetailRow(label: "Extension Template", value: extensionTemplate)
                            }
                            
                            if let serviceTemplate = vrf.serviceVrfTemplate, !serviceTemplate.isEmpty {
                                VRFDetailRow(label: "Service VRF Template", value: serviceTemplate)
                            }
                        }
                        
                        // Connection Information
                        VRFDetailSection(title: "Connection Details", icon: "link") {
                            VRFDetailRow(label: "Server", value: serverIP)
                            VRFDetailRow(label: "User", value: username)
                        }
                        
                        Spacer()
                    }
                    .padding()
                }
            } else {
                // No Selection State
                VStack(spacing: 20) {
                    Image(systemName: "sidebar.left")
                        .font(.system(size: 64))
                        .foregroundColor(.secondary)
                    
                    Text("Select a VRF")
                        .font(.title)
                        .fontWeight(.medium)
                        .foregroundColor(.secondary)
                    
                    Text("Choose a VRF from the sidebar to view detailed information")
                        .font(.body)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle(selectedVRF?.vrfName ?? "VRF Details")
        .navigationSubtitle(selectedVRF != nil ? "Fabric: \(fabricName)" : "")
    }
}

// MARK: - VRF Detail Components
struct VRFDetailSection<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content
    
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: icon)
                    .foregroundColor(.blue)
                Text(title)
                    .font(.headline)
                    .fontWeight(.semibold)
            }
            
            VStack(alignment: .leading, spacing: 8) {
                content
            }
            .padding()
            .background(Color(NSColor.controlBackgroundColor))
            .cornerRadius(8)
        }
    }
}

struct VRFDetailRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label)
                .font(.body)
                .fontWeight(.medium)
                .foregroundColor(.secondary)
                .frame(minWidth: 120, alignment: .leading)
            
            Text(value)
                .font(.body)
                .foregroundColor(.primary)
                .textSelection(.enabled)
            
            Spacer()
        }
    }
}

// MARK: - Preview
struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

