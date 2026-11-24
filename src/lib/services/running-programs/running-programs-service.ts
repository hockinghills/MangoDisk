import { invoke } from '@tauri-apps/api/core';

import type { RunningProgramsSnapshot } from '@/lib/models/running-programs/running-programs';

export class RunningProgramsService {
  /** With `useAdministratorRights`, the desktop asks for a password before the scan reads other users' processes. */
  static scan(useAdministratorRights: boolean): Promise<RunningProgramsSnapshot> {
    return invoke<RunningProgramsSnapshot>('scan_running_programs', { useAdministratorRights });
  }

  static cancelScan(): Promise<void> {
    return invoke<void>('cancel_running_programs_scan');
  }
}
