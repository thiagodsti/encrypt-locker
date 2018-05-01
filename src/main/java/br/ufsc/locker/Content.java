package br.ufsc.locker;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.io.Serializable;
import java.util.Objects;

@JsonSerialize
public class Content implements Serializable {

    private String fileName;
    private String key;

    public Content() {

    }

    public Content(String fileName, String key) {
        this.fileName = fileName;
        this.key = key;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Content content = (Content) o;
        return Objects.equals(fileName, content.fileName) &&
                Objects.equals(key, content.key);
    }

    @Override
    public int hashCode() {
        return Objects.hash(fileName, key);
    }
}
