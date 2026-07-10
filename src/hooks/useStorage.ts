import { useState, useEffect } from 'react';
import { packStorage, unpackStorage } from '../utils/security';

export function useStoredState<T>(
  key: string,
  initialValue: T,
  storage: 'local' | 'session' = 'local'
): [T, (value: T) => void] {
  const [storedValue, setStoredValue] = useState<T>(() => {
    try {
      const storageRef = storage === 'local' ? localStorage : sessionStorage;
      const item = storageRef.getItem(key);
      if (!item) return initialValue;
      const unpacked = unpackStorage(item);
      return unpacked ? JSON.parse(unpacked) : initialValue;
    } catch {
      return initialValue;
    }
  });

  const setValue = (value: T) => {
    setStoredValue(value);
    try {
      const storageRef = storage === 'local' ? localStorage : sessionStorage;
      const json = JSON.stringify(value);
      const packed = packStorage(json);
      storageRef.setItem(key, packed);
    } catch (e) {
      console.error(`Failed to persist ${key}:`, e);
    }
  };

  return [storedValue, setValue];
}

export function useBooleanState(key: string, defaultValue = false): [boolean, (val: boolean) => void] {
  const [value, setValue] = useStoredState<boolean>(key, defaultValue);
  return [value, setValue];
}
