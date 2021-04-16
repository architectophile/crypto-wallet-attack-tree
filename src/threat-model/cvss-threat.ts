import { AV, AC, PR, UI, TC, EX, EQ } from "./cvss";

export const TH_INSTALL_MALWARE: number[] = [AV.L, AC.L, PR.L, UI.R, TC.M, EX.P, EQ.S];
export const TH_SHOULDER_SURFING: number[] = [AV.P, AC.M, PR.N, UI.R, TC.N, EX.L, EQ.S];
export const TH_EVIL_MAID: number[] = [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.S];
export const TH_FAKE_BIOMETRICS: number[] = [AV.P, AC.H, PR.N, UI.N, TC.N, EX.P, EQ.P];
export const TH_BRUTE_FORCE: number[] = [AV.N, AC.M, PR.N, UI.N, TC.E, EX.L, EQ.P];
export const TH_WEAK_SIGNATURE: number[] = [AV.N, AC.M, PR.N, UI.N, TC.E, EX.P, EQ.P];
export const TH_NONCE_REUSE: number[] = [AV.N, AC.M, PR.N, UI.N, TC.E, EX.P, EQ.S];
export const TH_PHYSICAL_ATTACK: number[] = [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.P];
export const TH_CONNECT_DEBUGGER: number[] = [AV.P, AC.M, PR.N, UI.N, TC.H, EX.P, EQ.S];
export const TH_ROWHAMMER: number[] = [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.P];
export const TH_COLD_BOOT: number[] = [AV.P, AC.H, PR.N, UI.N, TC.M, EX.E, EQ.P];
export const TH_BUFFER_OVERFLOW: number[] = [AV.A, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S];
export const TH_DECRYPT_DATA: number[] = [AV.N, AC.M, PR.N, UI.N, TC.E, EX.P, EQ.S];
export const TH_SW_REVERSE_ENGINEERING: number[] = [
  AV.N,
  AC.M,
  PR.N,
  UI.N,
  TC.H,
  EX.P, 
  EQ.S
];
export const TH_SW_SUPPLY_CHAIN: number[] = [AV.N, AC.M, PR.N, UI.R, TC.H, EX.E, EQ.S];
export const TH_SOCIAL_ENGINEERING: number[] = [AV.N, AC.M, PR.L, UI.R, TC.H, EX.L, EQ.S];
export const TH_ROUGE_AP: number[] = [AV.L, AC.M, PR.N, UI.N, TC.N, EX.P, EQ.P];
export const TH_REMOVABLE_MEDIA: number[] = [AV.P, AC.L, PR.N, UI.N, TC.M, EX.L, EQ.S];
export const TH_EXECUTE_KEY_LOGGING: number[] = [AV.N, AC.L, PR.L, UI.R, TC.N, EX.L, EQ.S];
export const TH_EXECUTE_SCREEN_RECORDING: number[] = [AV.N, AC.L, PR.L, UI.R, TC.N, EX.L, EQ.S];
export const TH_EXECUTE_CLIPBOARD_HIJACKING: number[] = [AV.N, AC.L, PR.N, UI.R, TC.N, EX.L, EQ.S];
export const TH_EXECUTE_RANSOMWARE: number[] = [AV.N, AC.L, PR.L, UI.N, TC.N, EX.P, EQ.S];
export const TH_EXECUTE_NETWORK_PACKET_SNIFFING: number[] = [AV.N, AC.L, PR.N, UI.R, TC.N, EX.L, EQ.S];
export const TH_EXECUTE_USB_PACKET_SNIFFING: number[] = [AV.N, AC.L, PR.L, UI.R, TC.N, EX.P, EQ.S];
export const TH_ROOT_TOOLKIT: number[] = [AV.P, AC.M, PR.H, UI.R, TC.M, EX.E, EQ.S];
export const TH_BYPASS_USER_CONFIRMATION: number[] = [
  AV.P,
  AC.L,
  PR.N,
  UI.R,
  TC.N,
  EX.L, 
  EQ.S
];
export const TH_FACTORY_RESET_DISK_FORMATTING: number[] = [
  AV.P,
  AC.L,
  PR.N,
  UI.N,
  TC.M, 
  EX.L, 
  EQ.S
];
export const TH_ACCESS_PHYSICALLY: number[] = [AV.P, AC.H, PR.N, UI.N, TC.N, EX.L, EQ.S];
export const TH_TRY_INVALID_PIN: number[] = [AV.P, AC.L, PR.N, UI.N, TC.N, EX.L, EQ.S];
export const TH_DNS_SPOOFING: number[] = [AV.N, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S];
export const TH_IP_ADDR_SPOOFING: number[] = [AV.N, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S];
export const TH_ARP_SPOOFING: number[] = [AV.A, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S];
export const TH_RESOURCE_STARVATION: number[] = [AV.N, AC.H, PR.N, UI.N, TC.H, EX.P, EQ.P];
export const TH_SQL_INJECTION: number[] = [AV.N, AC.H, PR.N, UI.N, TC.H, EX.E, EQ.S];
