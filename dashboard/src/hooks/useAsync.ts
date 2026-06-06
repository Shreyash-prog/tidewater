import { useEffect, useState } from "react";

interface AsyncState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

/** Run an async loader whenever `deps` change. Cancels stale results. */
export function useAsync<T>(loader: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({
    data: null,
    error: null,
    loading: true,
  });

  useEffect(() => {
    let active = true;
    setState({ data: null, error: null, loading: true });
    loader()
      .then((data) => {
        if (active) setState({ data, error: null, loading: false });
      })
      .catch((err: unknown) => {
        if (active) {
          const message = err instanceof Error ? err.message : String(err);
          setState({ data: null, error: message, loading: false });
        }
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return state;
}
