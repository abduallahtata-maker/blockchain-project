// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title HealthDataChain - Secure patient data sharing and access logging using blockchain (with nonce protection)
contract HealthDataChain {
    address public owner;

    // Struct for healthcare providers
    struct Provider {
        bool registered;
        string meta;
    }

    // Struct for patients
    struct Patient {
        bool registered;
        string meta;
        mapping(address => bool) accessGranted;  // provider → access allowed
        bytes32[] recordHashes;                  // uploaded data hashes
    }

    // Mappings
    mapping(address => Provider) public providers;
    mapping(address => Patient) private patients;
    mapping(address => bool) public auditors;

    // Nonce mapping for replay protection (per provider)
    mapping(address => uint256) public nonces;

    // Events
    event ProviderRegistered(address indexed provider, string meta);
    event PatientRegistered(address indexed patient, string meta);
    event RecordUploaded(
        address indexed provider,
        address indexed patient,
        bytes32 dataHash,
        uint256 nonce,
        uint256 timestamp
    );
    event AccessGranted(address indexed patient, address indexed provider);
    event AccessRevoked(address indexed patient, address indexed provider);

    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyProvider() {
        require(providers[msg.sender].registered, "Not provider");
        _;
    }

    modifier onlyPatient() {
        require(patients[msg.sender].registered, "Not patient");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // ------------------------
    // Registration Functions
    // ------------------------

    function registerProvider(address provider, string calldata meta) external onlyOwner {
        providers[provider] = Provider(true, meta);
        nonces[provider] = 0; // Initialize provider's nonce to 0
        emit ProviderRegistered(provider, meta);
    }

    function registerPatient(address patient, string calldata meta) external onlyOwner {
        patients[patient].registered = true;
        patients[patient].meta = meta;
        emit PatientRegistered(patient, meta);
    }

    // ------------------------
    // Access Control
    // ------------------------

    function grantAccess(address provider) external onlyPatient {
        patients[msg.sender].accessGranted[provider] = true;
        emit AccessGranted(msg.sender, provider);
    }

    function revokeAccess(address provider) external onlyPatient {
        patients[msg.sender].accessGranted[provider] = false;
        emit AccessRevoked(msg.sender, provider);
    }

    // ------------------------
    // Record Uploading (with Nonce)
    // ------------------------

    /// @notice Upload a medical record hash (IPFS CID or keccak256 hash)
    /// @param patient The address of the patient
    /// @param dataHash The hash of the data
    /// @param nonce The next expected nonce (must be current + 1)
    function uploadRecord(address patient, bytes32 dataHash, uint256 nonce) external onlyProvider {
        require(patients[patient].registered, "Patient not registered");
        require(patients[patient].accessGranted[msg.sender], "No access granted");
        require(nonce == nonces[msg.sender] + 1, "Invalid nonce (replay or out of order)");

        // Update provider nonce and store record hash
        nonces[msg.sender] = nonce;
        patients[patient].recordHashes.push(dataHash);

        emit RecordUploaded(msg.sender, patient, dataHash, nonce, block.timestamp);
    }

    // ------------------------
    // Viewing and Auditing
    // ------------------------

    function viewRecords(address patient) external view returns (bytes32[] memory) {
        require(
            msg.sender == patient || patients[patient].accessGranted[msg.sender] || auditors[msg.sender],
            "Access denied"
        );
        return patients[patient].recordHashes;
    }

    function addAuditor(address auditor) external onlyOwner {
        auditors[auditor] = true;
    }
}
