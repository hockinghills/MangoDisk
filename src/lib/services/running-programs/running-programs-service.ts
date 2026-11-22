import { invoke } from '@tauri-apps/api/core';

import type { RunningProgramsSnapshot } from '@/lib/models/running-programs/running-programs';

export class RunningProgramsService {
  static scan(): Promise<RunningProgramsSnapshot> {
    return invoke<RunningProgramsSnapshot>('scan_running_programs');
  }

  static cancelScan(): Promise<void> {
    return invoke<void>('cancel_running_programs_scan');
  }
}
