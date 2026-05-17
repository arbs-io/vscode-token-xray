import { Memento } from "vscode";

export class LocalStorageService {

  constructor(private readonly storage: Memento) { }

  public getValue<T>(key: string): T {
    return this.storage.get<T>(key, "" as T);
  }

  public setValue<T>(key: string, value: T) {
    this.storage.update(key, value);
  }
}
